from dataclasses import dataclass
from datetime import datetime

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction

from orgaccess.access import log_access, visible_private_items
from orgaccess.models import PrivateItem, User


PRIVATE_ITEM_KINDS = frozenset({
    "chat",
    "note",
    "preference",
})

MAX_CONTENT_LENGTH = 100_000


@dataclass(frozen=True, slots=True)
class PrivateItemResult:
    id: int
    kind: str
    content: str
    created_at: datetime


def _active_actor(user: User) -> User:
    """
    Resolve the current database identity.

    Never trust stale authentication objects for private-data access.
    """

    if not isinstance(user, User) or user.pk is None:
        log_access(
            None,
            action="private_item.access.denied",
            object_type="PrivateItem",
            allowed=False,
            detail="Missing or invalid user identity.",
        )
        raise PermissionDenied("A valid authenticated user is required.")

    actor = User.objects.filter(pk=user.pk).first()

    if actor is None or not actor.is_active:
        log_access(
            actor,
            action="private_item.access.denied",
            object_type="PrivateItem",
            allowed=False,
            detail="Missing or inactive user.",
        )
        raise PermissionDenied("Private data is unavailable.")

    return actor


def _validate_payload(kind: str, content: str) -> None:
    if not isinstance(kind, str) or kind not in PRIVATE_ITEM_KINDS:
        raise ValidationError("Unsupported private item type.")

    if not isinstance(content, str) or not content.strip():
        raise ValidationError("Private item content cannot be empty.")

    if len(content) > MAX_CONTENT_LENGTH:
        raise ValidationError(
            f"Content cannot exceed {MAX_CONTENT_LENGTH} characters."
        )


def _result(item: PrivateItem) -> PrivateItemResult:
    return PrivateItemResult(
        id=item.pk,
        kind=item.kind,
        content=item.content,
        created_at=item.created_at,
    )


def list_private_items_for_user(
    *,
    user: User,
    kind: str | None = None,
    limit: int = 50,
) -> tuple[PrivateItemResult, ...]:
    """List only the requesting employee's private items."""

    actor = _active_actor(user)

    if kind is not None and kind not in PRIVATE_ITEM_KINDS:
        raise ValidationError("Unsupported private item type.")

    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValidationError("Limit must be between 1 and 100.")

    queryset = visible_private_items(actor)

    if kind is not None:
        queryset = queryset.filter(kind=kind)

    items = list(
        queryset.order_by("-created_at", "-pk")[:limit]
    )

    log_access(
        actor,
        action="private_item.list",
        object_type="PrivateItem",
        object_ids=[item.pk for item in items],
        allowed=True,
        detail=f"Retrieved {len(items)} private items.",
    )

    return tuple(_result(item) for item in items)


def get_private_item_for_user(
    *,
    user: User,
    item_id: int,
) -> PrivateItemResult:
    """Retrieve one private item owned by the requesting employee."""

    actor = _active_actor(user)

    if type(item_id) is not int or item_id < 1:
        raise ValidationError("Invalid private item ID.")

    item = visible_private_items(actor).filter(pk=item_id).first()

    if item is None:
        log_access(
            actor,
            action="private_item.read",
            object_type="PrivateItem",
            object_ids=[item_id],
            allowed=False,
            detail="Item not found or not owned by requester.",
        )

        raise PermissionDenied("Private item is unavailable.")

    log_access(
        actor,
        action="private_item.read",
        object_type="PrivateItem",
        object_ids=[item.pk],
        allowed=True,
        detail="Private item retrieved.",
    )

    return _result(item)


def create_private_item_for_user(
    *,
    user: User,
    kind: str,
    content: str,
) -> PrivateItemResult:
    """Create a private item owned by the authenticated employee."""

    actor = _active_actor(user)

    _validate_payload(kind, content)

    with transaction.atomic():
        item = PrivateItem.objects.create(
            owner=actor,
            kind=kind,
            content=content,
        )

        log_access(
            actor,
            action="private_item.create",
            object_type="PrivateItem",
            object_ids=[item.pk],
            allowed=True,
            detail=f"Created private {kind} item.",
        )

    return _result(item)


def update_private_item_for_user(
    *,
    user: User,
    item_id: int,
    content: str,
    kind: str | None = None,
) -> PrivateItemResult:
    """Update only a private item belonging to the requesting employee."""

    actor = _active_actor(user)

    if type(item_id) is not int or item_id < 1:
        raise ValidationError("Invalid private item ID.")

    with transaction.atomic():
        item = (
            visible_private_items(actor)
            .select_for_update()
            .filter(pk=item_id)
            .first()
        )

        if item is None:
            log_access(
                actor,
                action="private_item.update",
                object_type="PrivateItem",
                object_ids=[item_id],
                allowed=False,
                detail="Item not found or not owned by requester.",
            )
        else:
            new_kind = kind if kind is not None else item.kind

            _validate_payload(new_kind, content)

            item.kind = new_kind
            item.content = content

            item.save(update_fields=["kind", "content"])

            log_access(
                actor,
                action="private_item.update",
                object_type="PrivateItem",
                object_ids=[item.pk],
                allowed=True,
                detail="Private item updated.",
            )

    if item is None:
        raise PermissionDenied("Private item is unavailable.")

    return _result(item)


def delete_private_item_for_user(
    *,
    user: User,
    item_id: int,
) -> None:
    """Delete only a private item owned by the requesting employee."""

    actor = _active_actor(user)

    if type(item_id) is not int or item_id < 1:
        raise ValidationError("Invalid private item ID.")

    with transaction.atomic():
        item = (
            visible_private_items(actor)
            .select_for_update()
            .filter(pk=item_id)
            .first()
        )

        if item is None:
            log_access(
                actor,
                action="private_item.delete",
                object_type="PrivateItem",
                object_ids=[item_id],
                allowed=False,
                detail="Item not found or not owned by requester.",
            )
        else:
            item.delete()

            log_access(
                actor,
                action="private_item.delete",
                object_type="PrivateItem",
                object_ids=[item_id],
                allowed=True,
                detail="Private item deleted.",
            )

    if item is None:
        raise PermissionDenied("Private item is unavailable.")