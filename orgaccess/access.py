"""
The permission engine. Every retrieval and every tool lookup goes through here.

Document access rule (a record is visible if ANY of these is true):
  1. The user is its subject (own payslip, own appraisal).          [any label]
  2. The user owns it and it is not RESTRICTED (own drafts).
  3. The user holds an active group listed in allowed_groups.       [explicit grant]
  4. It is PUBLIC or INTERNAL.                                      [company-wide]
  5. It is DEPARTMENTAL/CONFIDENTIAL, the user's clearance reaches the label, AND
       - the record belongs to the user's own department, OR
       - the user is an Executive or an auditor (company-wide, never RESTRICTED).
RESTRICTED records are reachable only through rules 1 and 3.
Deactivated users see nothing. Nothing is cached, so role/department changes apply
on the very next request.
"""
from django.db.models import Q
from django.utils import timezone

from .models import AccessGroup, AuditLog, Level, PrivateItem, Sensitivity, TemporaryGrant, ToolGrant, User, ToolTier

CLEARANCE_BY_LEVEL = {
    Level.EXECUTIVE: Sensitivity.CONFIDENTIAL,
    Level.DEPT_HEAD: Sensitivity.CONFIDENTIAL,
    Level.MANAGER: Sensitivity.CONFIDENTIAL,
    Level.SUPERVISOR: Sensitivity.DEPARTMENTAL,
    Level.OFFICER: Sensitivity.DEPARTMENTAL,
    Level.JUNIOR: Sensitivity.INTERNAL,
}

V1_AVAILABLE_TOOL_TIERS = frozenset({
    ToolTier.READ,
    ToolTier.DRAFT,
})

def active_group_ids(user, now=None):
    """Permanent memberships plus unexpired, unrevoked temporary grants."""
    now = now or timezone.now()
    ids = set(user.access_groups.values_list("id", flat=True))
    ids |= set(
        TemporaryGrant.objects.filter(user=user, revoked_at__isnull=True, expires_at__gt=now)
        .values_list("group_id", flat=True)
    )
    return ids


def active_group_codes(group_ids):
    return set(AccessGroup.objects.filter(id__in=group_ids).values_list("code", flat=True))


def clearance_for(level, group_codes):
    clearance = CLEARANCE_BY_LEVEL.get(level, Sensitivity.INTERNAL)
    if "auditors" in group_codes:
        clearance = max(clearance, Sensitivity.CONFIDENTIAL)
    return clearance


def visible_to(user, qs, now=None):
    """Filter any queryset of an AccessControlled model (Document, DocumentChunk) for this user."""
    if not user.is_active:
        return qs.none()

    group_ids = active_group_ids(user, now)
    codes = active_group_codes(group_ids)
    level = user.level
    clearance = clearance_for(level, codes)

    allowed = Q(subject=user)
    allowed |= Q(owner=user, sensitivity__lt=Sensitivity.RESTRICTED)
    if group_ids:
        allowed |= Q(allowed_groups__in=group_ids)
    allowed |= Q(sensitivity__lte=Sensitivity.INTERNAL)

    scoped_labels = [s for s in (Sensitivity.DEPARTMENTAL, Sensitivity.CONFIDENTIAL) if s <= clearance]
    if scoped_labels:
        scoped = Q(sensitivity__in=scoped_labels)
        if level == Level.EXECUTIVE or "auditors" in codes:
            allowed |= scoped
        elif user.department_id:
            allowed |= scoped & Q(department_id=user.department_id)

    return qs.filter(allowed).distinct()


def can_view(user, obj, now=None):
    return visible_to(user, type(obj).objects.filter(pk=obj.pk), now).exists()


def visible_private_items(user):
    """Owner only. Managers, admins and executives get no path in."""
    if not user.is_active:
        return PrivateItem.objects.none()
    return PrivateItem.objects.filter(owner=user)


def report_ids(user):
    """All direct and indirect reports (breadth-first; cycle-safe)."""
    seen = {user.id}
    frontier = [user.id]
    while frontier:
        children = list(
            User.objects.filter(manager_id__in=frontier, is_active=True)
            .exclude(id__in=seen)
            .values_list("id", flat=True)
        )
        seen.update(children)
        frontier = children
    seen.discard(user.id)
    return seen


# ---------- tools ----------

def effective_grants(user, now=None):
    if not user.is_active:
        return []
    level = user.level
    group_ids = active_group_ids(user, now)
    qs = ToolGrant.objects.select_related("tool", "department", "required_group").filter(
        level_min__lte=level, level_max__gte=level
    )
    if level != Level.EXECUTIVE:
        qs = qs.filter(Q(department__isnull=True) | Q(department_id=user.department_id))
    return [g for g in qs if g.required_group_id is None or g.required_group_id in group_ids]


def tools_for(user, now=None):
    """
    Return all tools for which the user has effective grants.

    This includes future capability tiers such as ACT.
    It does not establish whether a tool is enabled for runtime discovery.
    """
    out = {}

    for g in effective_grants(user, now):
        out.setdefault(g.tool.name, []).append(g)

    return out

def available_tools_for(user, now=None):
    """
    Return tools that the Actor may discover and use in version one.

    The user's organizational grants are still enforced first.
    Only supported tool tiers are exposed.
    """

    if not user.is_active:
        return {}

    granted_tools = tools_for(user, now)

    return {
        name: grants
        for name, grants in granted_tools.items()
        if grants and grants[0].tool.tier in V1_AVAILABLE_TOOL_TIERS
    }


def can_discover_tool(user, tool_name, now=None):
    """
    Check whether a tool is both authorized and enabled for runtime use.
    """

    return tool_name in available_tools_for(user, now)


def can_use_tool(user, tool_name, now=None):
    return tool_name in tools_for(user, now)


def approval_limit(user, tool_name, now=None):
    limits = [g.approval_limit_ngn for g in tools_for(user, now).get(tool_name, []) if g.approval_limit_ngn is not None]
    return max(limits) if limits else None


def scopes_for(user, tool_name, now=None):
    return {g.scope for g in tools_for(user, now).get(tool_name, [])}


def log_access(user, action, object_type="", object_ids=(), allowed=True, detail=""):
    return AuditLog.objects.create(
        user=user, action=action, object_type=object_type,
        object_ids=",".join(str(i) for i in object_ids), allowed=allowed, detail=detail,
    )
