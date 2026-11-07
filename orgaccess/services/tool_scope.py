from dataclasses import dataclass

from django.core.exceptions import PermissionDenied
from django.db.models import QuerySet

from orgaccess.access import (
    available_tools_for,
    report_ids,
    visible_to,
)
from orgaccess.models import (
    AccessControlled,
    Scope,
    User,
)


@dataclass(frozen=True)
class ScopeContext:
    """Verified scope granted to a user for a particular tool."""

    user: User
    tool_name: str
    scope: Scope
    subject_user_ids: frozenset[int] | None = None
    department_id: int | None = None

    @property
    def aggregate_only(self) -> bool:
        return self.scope == Scope.COMPANY_AGGREGATE


def resolve_tool_scope(
    user: User,
    tool_name: str,
    requested_scope: str | Scope,
    now=None,
) -> ScopeContext:
    """
    Resolve and authorize an explicitly requested tool scope.

    Uses a fresh database copy of the user so stale role,
    department and activation information is not trusted.
    """

    if not isinstance(user, User) or user.pk is None:
        raise PermissionDenied("A valid authenticated staff member is required.")

    try:
        current_user = (
            User.objects.select_related("role", "department")
            .get(pk=user.pk)
        )
    except User.DoesNotExist:
        raise PermissionDenied("Staff account does not exist.")

    if not current_user.is_active:
        raise PermissionDenied("Inactive staff cannot access tools.")

    try:
        scope = Scope(requested_scope)
    except (TypeError, ValueError):
        raise PermissionDenied("Invalid or unsupported tool scope.")

    # Only organizationally authorized and runtime-available
    # tools can proceed to scope resolution.
    available = available_tools_for(current_user, now)
    grants = available.get(tool_name, [])

    if not any(grant.scope == scope for grant in grants):
        raise PermissionDenied(
            f"No permission to use {tool_name} at scope {scope}."
        )

    if scope == Scope.SELF:
        return ScopeContext(
            user=current_user,
            tool_name=tool_name,
            scope=scope,
            subject_user_ids=frozenset({current_user.pk}),
        )

    if scope == Scope.TEAM:
        return ScopeContext(
            user=current_user,
            tool_name=tool_name,
            scope=scope,
            subject_user_ids=frozenset(report_ids(current_user)),
        )

    if scope == Scope.DEPARTMENT:
        if current_user.department_id is None:
            raise PermissionDenied(
                "Department scope requires an assigned department."
            )

        return ScopeContext(
            user=current_user,
            tool_name=tool_name,
            scope=scope,
            department_id=current_user.department_id,
        )

    # COMPANY, COMPANY_AGGREGATE and ACL do not receive
    # unrestricted employee ID sets.
    return ScopeContext(
        user=current_user,
        tool_name=tool_name,
        scope=scope,
    )


def filter_queryset_for_scope(
    queryset: QuerySet,
    context: ScopeContext,
    *,
    user_field: str | None = None,
    department_field: str | None = None,
) -> QuerySet:
    """
    Apply the authorized tool scope to a trusted application queryset.

    user_field and department_field must be supplied by trusted
    server-side tool adapters, never by the LLM or the requesting user.

    AccessControlled models always retain their underlying document ACL.
    """

    if not isinstance(queryset, QuerySet):
        raise TypeError("Expected a Django QuerySet.")

    if not isinstance(context, ScopeContext):
        raise TypeError("A verified ScopeContext is required.")

    # Revalidate the user's current account, grants and reporting line.
    # This also catches revocations after the initial scope resolution.
    context = resolve_tool_scope(
        context.user,
        context.tool_name,
        context.scope,
    )

    is_acl_model = issubclass(queryset.model, AccessControlled)

    # Organizational data scope never overrides document ACLs.
    if is_acl_model:
        queryset = visible_to(context.user, queryset)

    if context.scope == Scope.ACL:
        if not is_acl_model:
            raise PermissionDenied(
                "ACL scope can only be applied to access-controlled models."
            )

        return queryset

    if context.scope == Scope.SELF:
        if not user_field:
            raise ValueError("SELF scope requires a user field mapping.")

        return queryset.filter(
            **{
                f"{user_field}__in": context.subject_user_ids,
            }
        )

    if context.scope == Scope.TEAM:
        if not user_field:
            raise ValueError("TEAM scope requires a user field mapping.")

        return queryset.filter(
            **{
                f"{user_field}__in": context.subject_user_ids,
            }
        )

    if context.scope == Scope.DEPARTMENT:
        if not department_field:
            raise ValueError(
                "DEPARTMENT scope requires a department field mapping."
            )

        return queryset.filter(
            **{
                department_field: context.department_id,
            }
        )

    if context.scope == Scope.COMPANY_AGGREGATE:
        raise PermissionDenied(
            "Company aggregate scope cannot expose raw records. "
            "Use an approved aggregation service."
        )

    if context.scope == Scope.COMPANY:
        # The queryset must already be restricted to the data source
        # authorized for this tool. AccessControlled models have also
        # been filtered through visible_to() above.
        return queryset

    raise PermissionDenied("Unsupported scope.")