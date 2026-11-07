from dataclasses import dataclass

from django.core.exceptions import PermissionDenied
from django.db.models import Q, QuerySet

from orgaccess.access import log_access
from orgaccess.models import (
    DataSource,
    DataSourceAccessMode,
    User,
)


@dataclass(frozen=True, slots=True)
class DataSourceAccess:
    """Resolved permission to access a registered source."""

    user: User
    source: DataSource

    @property
    def requires_item_acl(self) -> bool:
        return self.source.access_mode == DataSourceAccessMode.ITEM_ACL


def _current_active_user(user: User) -> User:
    """Resolve the current database identity, not a stale user object."""

    if not isinstance(user, User) or user.pk is None:
        raise PermissionDenied("A valid authenticated user is required.")

    actor = (
        User.objects.select_related("role", "department")
        .filter(pk=user.pk)
        .first()
    )

    if actor is None or not actor.is_active:
        raise PermissionDenied("Data source access is unavailable.")

    return actor


def _eligible_sources(actor: User) -> QuerySet:
    """
    Construct the source queryset permitted by the employee's
    department and hierarchy level.

    A lower hierarchy number represents greater seniority.
    """

    policy = (
        Q(access_mode=DataSourceAccessMode.COMPANY)
        | Q(access_mode=DataSourceAccessMode.ITEM_ACL)
    )

    if actor.department_id is not None:
        policy |= Q(
            access_mode=DataSourceAccessMode.DEPARTMENT,
            owner_department_id=actor.department_id,
        )

    return (
        DataSource.objects.filter(
            is_active=True,
            minimum_level__gte=actor.level,
        )
        .filter(policy)
        .select_related("owner_department")
    )


def data_sources_for_user(user: User) -> QuerySet:
    """
    Return registered sources the requesting employee is
    eligible to access at the source-policy level.

    ITEM_ACL sources still require individual record authorization.
    """

    actor = _current_active_user(user)

    return _eligible_sources(actor)


def resolve_data_source_access(
    user: User,
    data_source: DataSource | int,
) -> DataSourceAccess:
    """
    Resolve access to one registered data source.

    Does not grant access to individual documents or records.
    """

    actor = _current_active_user(user)

    source_id = (
        data_source.pk
        if isinstance(data_source, DataSource)
        else data_source
    )

    if type(source_id) is not int or source_id < 1:
        raise PermissionDenied("Data source access is unavailable.")

    source = _eligible_sources(actor).filter(pk=source_id).first()

    if source is None:
        log_access(
            actor,
            action="data_source.access.denied",
            object_type="DataSource",
            object_ids=[source_id],
            allowed=False,
            detail="Source unavailable or access policy not satisfied.",
        )

        raise PermissionDenied("Data source access is unavailable.")

    return DataSourceAccess(
        user=actor,
        source=source,
    )