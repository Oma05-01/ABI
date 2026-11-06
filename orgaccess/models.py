"""
Org structure, permissions and tool grants for the local business agent.

Design rules baked into these models
------------------------------------
* Lower level number = more senior (1 = Executive ... 6 = Junior).
* Everything is deny-by-default: new documents are RESTRICTED until someone
  deliberately lowers the label.
* Access to documents and chunks is decided ONLY by orgaccess.access.visible_to().
  Never filter in a prompt.
* Chunks carry a copy of their parent document's ACL so retrieval can filter
  before anything reaches the model.
"""
from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.db.models import F, Q
from django.core.exceptions import ValidationError

class Level(models.IntegerChoices):
    EXECUTIVE = 1, "Executive"
    DEPT_HEAD = 2, "Department head"
    MANAGER = 3, "Manager"
    SUPERVISOR = 4, "Supervisor / senior officer"
    OFFICER = 5, "Officer"
    JUNIOR = 6, "Junior / frontline"


class Sensitivity(models.IntegerChoices):
    PUBLIC = 0, "Public"
    INTERNAL = 1, "Internal (all staff)"
    DEPARTMENTAL = 2, "Departmental"
    CONFIDENTIAL = 3, "Confidential (department, manager level and up)"
    RESTRICTED = 4, "Restricted (explicit grants only)"


class ToolTier(models.TextChoices):
    READ = "read", "Read (runs freely within permissions)"
    DRAFT = "draft", "Draft (output goes to the user for review)"
    ACT = "act", "Act (needs human approval before anything executes)"


class Scope(models.TextChoices):
    SELF = "self", "Own records only"
    TEAM = "team", "The user's reporting line"
    DEPARTMENT = "department", "Own department"
    COMPANY_AGGREGATE = "company_aggregate", "Company-wide, aggregates only"
    COMPANY = "company", "Company-wide"
    ACL = "acl", "Whatever document ACLs allow"


class Department(models.Model):
    code = models.SlugField(max_length=20, unique=True)
    name = models.CharField(max_length=100)

    def __str__(self):
        return self.name


class Role(models.Model):
    code = models.SlugField(max_length=60, unique=True)
    title = models.CharField(max_length=100)
    department = models.ForeignKey(Department, null=True, blank=True, on_delete=models.PROTECT)
    level = models.PositiveSmallIntegerField(choices=Level.choices)

    def __str__(self):
        return self.title

    def clean(self):
        super().clean()

        if self.pk:
            conflicting_users = User.objects.filter(
                role_id=self.pk
            ).exclude(
                department_id=self.department_id
            )

            if conflicting_users.exists():
                raise ValidationError({
                    "department": (
                        "This role cannot be moved to another department "
                        "while assigned users would become inconsistent. "
                        "Create a new role and reassign those users first."
                    )
                })

    def save(self, *args, **kwargs):
        self.clean()
        return super().save(*args, **kwargs)


class AccessGroup(models.Model):
    """Cross-cutting groups: payroll-team, auditors, project groups, etc."""
    code = models.SlugField(max_length=40, unique=True)
    description = models.CharField(max_length=200, blank=True)

    def __str__(self):
        return self.code


class User(AbstractUser):
    employee_id = models.CharField(max_length=20, unique=True, null=True, blank=True)
    role = models.ForeignKey(Role, null=True, blank=True, on_delete=models.PROTECT)
    department = models.ForeignKey(Department, null=True, blank=True, on_delete=models.PROTECT)
    manager = models.ForeignKey(
        "self", null=True, blank=True, on_delete=models.SET_NULL, related_name="direct_reports"
    )
    access_groups = models.ManyToManyField(AccessGroup, blank=True, related_name="members")

    @property
    def level(self) -> int:
        # No role means least privilege.
        return self.role.level if self.role_id else Level.JUNIOR

    def __str__(self):
        return self.get_full_name() or self.username

    def clean(self):
        super().clean()

        if self.role_id:
            role_department_id = self.role.department_id

            if (
                    role_department_id is not None
                    and self.department_id != role_department_id
            ):
                raise ValidationError({
                    "department": (
                        "The user's department must match the department "
                        "assigned to their role. For department transfers, "
                        "change both assignments together."
                    )
                })

    def save(self, *args, **kwargs):
        self.clean()
        return super().save(*args, **kwargs)


class TemporaryGrant(models.Model):
    """Break-glass or time-limited group membership. Always has a reason and an expiry."""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="temporary_grants")
    group = models.ForeignKey(AccessGroup, on_delete=models.CASCADE)
    reason = models.TextField()
    granted_by = models.ForeignKey(User, null=True, on_delete=models.SET_NULL, related_name="+")
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)


class AccessControlled(models.Model):
    """
    ACL fields shared by Document and DocumentChunk.

    department      None means company-wide (only meaningful for PUBLIC/INTERNAL).
    sensitivity     defaults to RESTRICTED: deny by default.
    owner           creator. Sees their own non-restricted items.
    subject         the person the record is about (payslip, appraisal). Always sees it.
    allowed_groups  explicit EXTRA access. Groups extend access, they never narrow it.
                    To make something group-only, label it RESTRICTED.
    """
    department = models.ForeignKey(Department, null=True, blank=True, on_delete=models.PROTECT, related_name="+")
    sensitivity = models.PositiveSmallIntegerField(choices=Sensitivity.choices, default=Sensitivity.RESTRICTED)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    subject = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    allowed_groups = models.ManyToManyField(AccessGroup, blank=True, related_name="%(class)s_acl")

    class Meta:
        abstract = True


class Document(AccessControlled):
    title = models.CharField(max_length=200)
    body = models.TextField(blank=True)
    source = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title

    def sync_chunk_acl(self):
        """Synchronize child chunks with this document's ACL."""

        from orgaccess.services.document_acl import sync_document_chunks

        return sync_document_chunks(self)


class DocumentChunk(AccessControlled):
    document = models.ForeignKey(Document, on_delete=models.CASCADE, related_name="chunks")
    position = models.PositiveIntegerField(default=0)
    text = models.TextField()
    # In production add: embedding = VectorField(dimensions=...)  (pgvector)


class PrivateItem(models.Model):
    """Per-user private layer: chat history, notes, learned preferences. Owner only, no exceptions."""
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name="private_items")
    kind = models.CharField(max_length=20)  # chat | note | preference
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)


class Tool(models.Model):
    name = models.SlugField(max_length=60, unique=True)
    tier = models.CharField(max_length=10, choices=ToolTier.choices)
    description = models.CharField(max_length=200)

    def __str__(self):
        return f"{self.name} [{self.tier}]"


class ToolGrant(models.Model):
    """
    Who gets a tool. A grant applies to users whose level is in [level_min, level_max]
    (inclusive, 1 = most senior), optionally restricted to one department and/or one
    access group. Executives receive department-specific tools for every department.
    """
    tool = models.ForeignKey(Tool, on_delete=models.CASCADE, related_name="grants")
    level_min = models.PositiveSmallIntegerField(choices=Level.choices)
    level_max = models.PositiveSmallIntegerField(choices=Level.choices)
    department = models.ForeignKey(Department, null=True, blank=True, on_delete=models.CASCADE)
    required_group = models.ForeignKey(AccessGroup, null=True, blank=True, on_delete=models.CASCADE)
    scope = models.CharField(max_length=20, choices=Scope.choices, default=Scope.SELF)
    approval_limit_ngn = models.DecimalField(max_digits=14, decimal_places=2, null=True, blank=True)
    requires_second_approver = models.BooleanField(default=False)

    class Meta:
        constraints = [
            models.CheckConstraint(condition=Q(level_min__lte=F("level_max")), name="grant_level_range_valid"),
        ]


class AuditLog(models.Model):
    at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, null=True, on_delete=models.SET_NULL, related_name="+")
    action = models.CharField(max_length=60)
    object_type = models.CharField(max_length=60, blank=True)
    object_ids = models.TextField(blank=True)
    allowed = models.BooleanField(default=True)
    detail = models.TextField(blank=True)
