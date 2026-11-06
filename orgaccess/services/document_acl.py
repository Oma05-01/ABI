from collections.abc import Iterable

from django.db import transaction

from orgaccess.models import (
    AccessGroup,
    Department,
    Document,
    DocumentChunk,
    Sensitivity,
    User,
)


def _validated_group_ids(
    groups: Iterable[AccessGroup],
) -> list[int]:
    """Validate and normalize the access groups assigned to an ACL."""

    groups = list(groups)

    if any(not isinstance(group, AccessGroup) or group.pk is None for group in groups):
        raise ValueError("All access groups must be saved AccessGroup instances.")

    requested_ids = {group.pk for group in groups}

    existing_ids = set(
        AccessGroup.objects.filter(pk__in=requested_ids)
        .values_list("pk", flat=True)
    )

    if requested_ids != existing_ids:
        raise ValueError("One or more supplied access groups do not exist.")

    return sorted(existing_ids)


def _sync_locked_document_chunks(document: Document) -> int:
    """
    Copy the locked document's ACL onto all its existing chunks.

    The caller must already hold a transaction and a row lock
    on the parent document.
    """

    group_ids = list(
        document.allowed_groups.values_list("pk", flat=True)
    )

    chunks = DocumentChunk.objects.filter(document_id=document.pk)

    chunk_count = chunks.count()

    # Copy scalar ACL fields efficiently in one SQL UPDATE.
    chunks.update(
        department_id=document.department_id,
        sensitivity=document.sensitivity,
        owner_id=document.owner_id,
        subject_id=document.subject_id,
    )

    # Many-to-many relationships require separate operations.
    for chunk in chunks.only("pk").iterator(chunk_size=500):
        chunk.allowed_groups.set(group_ids)

    return chunk_count


@transaction.atomic
def sync_document_chunks(document: Document) -> int:
    """
    Synchronize every existing chunk with its parent document.

    Returns the number of synchronized chunks.
    """

    if document.pk is None:
        raise ValueError("Cannot synchronize chunks for an unsaved document.")

    locked_document = (
        Document.objects.select_for_update()
        .get(pk=document.pk)
    )

    return _sync_locked_document_chunks(locked_document)


@transaction.atomic
def update_document_acl(
    document: Document,
    *,
    department: Department | None,
    sensitivity: int,
    owner: User | None,
    subject: User | None,
    allowed_groups: Iterable[AccessGroup],
) -> Document:
    """
    Update a document ACL and propagate it to all existing chunks.

    All ACL fields are explicit. Passing None for department,
    owner or subject clears that field.
    """

    if document.pk is None:
        raise ValueError("Cannot update the ACL of an unsaved document.")

    if sensitivity not in Sensitivity.values:
        raise ValueError(f"Invalid document sensitivity: {sensitivity}")

    group_ids = _validated_group_ids(allowed_groups)

    # Lock the parent row so concurrent chunk creation and ACL
    # modifications cannot pass each other.
    locked_document = (
        Document.objects.select_for_update()
        .get(pk=document.pk)
    )

    locked_document.department = department
    locked_document.sensitivity = sensitivity
    locked_document.owner = owner
    locked_document.subject = subject

    locked_document.save(
        update_fields=[
            "department",
            "sensitivity",
            "owner",
            "subject",
        ]
    )

    locked_document.allowed_groups.set(group_ids)

    _sync_locked_document_chunks(locked_document)

    return locked_document


@transaction.atomic
def create_document_chunk(
    *,
    document: Document,
    position: int,
    text: str,
) -> DocumentChunk:
    """
    Create a chunk using the current ACL of its parent document.

    The parent row is locked to serialize this operation against
    document ACL modifications.
    """

    if document.pk is None:
        raise ValueError("Cannot create a chunk for an unsaved document.")

    locked_document = (
        Document.objects.select_for_update()
        .get(pk=document.pk)
    )

    chunk = DocumentChunk.objects.create(
        document=locked_document,
        position=position,
        text=text,
        department_id=locked_document.department_id,
        sensitivity=locked_document.sensitivity,
        owner_id=locked_document.owner_id,
        subject_id=locked_document.subject_id,
    )

    chunk.allowed_groups.set(
        locked_document.allowed_groups.values_list("pk", flat=True)
    )

    return chunk