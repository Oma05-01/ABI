from dataclasses import dataclass
from datetime import datetime

from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.db.models import Q

from orgaccess.access import log_access, visible_to
from orgaccess.models import (
    Document,
    DocumentChunk,
    Scope,
    User,
)
from orgaccess.services.tool_scope import resolve_tool_scope
from orgaccess.services.source_access import data_sources_for_user

DOCUMENT_READ_TOOLS = frozenset({
    "search_policies",
    "search_documents",
})

def _visible_documents(context, now=None):
    """
    Return documents satisfying both source authorization
    and their individual document ACL.

    Documents without a registered source are excluded.
    """

    eligible_source_ids = (
        data_sources_for_user(context.user)
        .values("pk")
    )

    queryset = (
        Document.objects
        .filter(data_source_id__in=eligible_source_ids)
        .select_related("data_source")
    )

    return visible_to(context.user, queryset, now)

@dataclass(frozen=True, slots=True)
class AuthorizedDocument:
    id: int
    title: str
    body: str
    source: str
    data_source_id: int
    data_source_code: str
    department_id: int | None
    sensitivity: int
    created_at: datetime


@dataclass(frozen=True, slots=True)
class AuthorizedChunk:
    id: int
    document_id: int
    document_title: str
    position: int
    text: str
    source: str
    data_source_id: int
    data_source_code: str


def _authorize_document_read(user, tool_name, now=None):
    """
    Resolve the requesting user's current identity, tool grant
    and ACL scope before allowing document retrieval.
    """

    if tool_name not in DOCUMENT_READ_TOOLS:
        raise PermissionDenied("This tool cannot perform document retrieval.")

    try:
        return resolve_tool_scope(
            user,
            tool_name,
            Scope.ACL,
            now=now,
        )

    except PermissionDenied:
        # Record denied attempts without exposing whether a document
        # or tool exists to the requesting user.
        user_id = getattr(user, "pk", None)

        actor = (
            User.objects.filter(pk=user_id).first()
            if user_id is not None
            else None
        )

        log_access(
            actor,
            action="document.access.denied",
            object_type="Document",
            allowed=False,
            detail="Tool authorization or ACL scope check failed.",
        )

        raise PermissionDenied(
            "The requested information is unavailable."
        ) from None


def _validate_search(query, limit):
    if not isinstance(query, str) or not query.strip():
        raise ValueError("A non-empty search query is required.")

    if len(query) > 500:
        raise ValueError("Search query exceeds 500 characters.")

    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("Search limit must be between 1 and 100.")

    return query.strip()


def _document_result(document):
    return AuthorizedDocument(
        id=document.pk,
        title=document.title,
        body=document.body,
        source=document.source,
        data_source_id=document.data_source_id,
        data_source_code=document.data_source.code,
        department_id=document.department_id,
        sensitivity=document.sensitivity,
        created_at=document.created_at,
    )


def get_document_for_user(
    *,
    user,
    document_id: int,
    tool_name: str,
    now=None,
) -> AuthorizedDocument:
    """Retrieve one document after tool and document ACL checks."""

    if type(document_id) is not int or document_id < 1:
        raise ValueError("A valid document ID is required.")

    context = _authorize_document_read(user, tool_name, now)

    result = None

    with transaction.atomic():
        document = (
            _visible_documents(context, now)
            .filter(pk=document_id)
            .first()
        )

        if document is None:
            log_access(
                context.user,
                action="document.read",
                object_type="Document",
                object_ids=[document_id],
                allowed=False,
                detail="Document not found or not authorized.",
            )
        else:
            result = _document_result(document)

            log_access(
                context.user,
                action="document.read",
                object_type="Document",
                object_ids=[document.pk],
                allowed=True,
                detail="Authorized document retrieval.",
            )

    if result is None:
        raise PermissionDenied(
            "The requested document is unavailable."
        )

    return result


def search_documents_for_user(
    *,
    user,
    query: str,
    tool_name: str,
    limit: int = 20,
    now=None,
) -> tuple[AuthorizedDocument, ...]:
    """Search documents visible to the requesting employee."""

    query = _validate_search(query, limit)

    context = _authorize_document_read(user, tool_name, now)

    with transaction.atomic():
        queryset = _visible_documents(context, now)

        queryset = queryset.filter(
            Q(title__icontains=query)
            | Q(body__icontains=query)
        ).order_by("pk")

        documents = list(queryset[:limit])

        results = tuple(
            _document_result(document)
            for document in documents
        )

        log_access(
            context.user,
            action="document.search",
            object_type="Document",
            object_ids=[document.id for document in documents],
            allowed=True,
            detail=f"Authorized search returned {len(results)} documents.",
        )

    return results


def search_chunks_for_user(
    *,
    user,
    query: str,
    tool_name: str,
    limit: int = 20,
    now=None,
) -> tuple[AuthorizedChunk, ...]:
    """
    Search authorized document chunks.

    Both the chunk ACL and the current parent document ACL
    must permit access.
    """

    query = _validate_search(query, limit)

    context = _authorize_document_read(user, tool_name, now)

    with transaction.atomic():
        # First establish which parent documents are visible.
        visible_document_ids = (
            _visible_documents(context, now)
            .values("pk")
        )

        # Then filter chunks by their own ACL as well as their
        # parent's current ACL.
        queryset = visible_to(
            context.user,
            DocumentChunk.objects.select_related(
                "document",
                "document__data_source",
            ),
            now,
        ).filter(
            document_id__in=visible_document_ids
        )

        chunks = list(
            queryset.filter(
                text__icontains=query
            ).order_by(
                "document_id",
                "position",
                "pk",
            )[:limit]
        )

        results = tuple(
            AuthorizedChunk(
                id=chunk.pk,
                document_id=chunk.document_id,
                document_title=chunk.document.title,
                position=chunk.position,
                text=chunk.text,
                source=chunk.document.source,
                data_source_id=chunk.document.data_source_id,
                data_source_code=chunk.document.data_source.code,
            )
            for chunk in chunks
        )

        log_access(
            context.user,
            action="document.chunk_search",
            object_type="DocumentChunk",
            object_ids=[chunk.id for chunk in chunks],
            allowed=True,
            detail=f"Authorized chunk search returned {len(results)} chunks.",
        )

    return results