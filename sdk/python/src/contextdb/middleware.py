"""Provider-neutral before/after turn middleware."""

from __future__ import annotations

import asyncio
import hashlib
import threading
from collections.abc import Mapping
from dataclasses import replace
from types import MappingProxyType
from typing import Any

from .client import AsyncContextDbClient, ContextDbClient
from .models import (
    AccessPolicy,
    ObserveRequest,
    ObserveResponse,
    RecallRequest,
    RecallResponse,
    RecallTrace,
    RequestContext,
)


def _turn_key(
    session_id: str,
    agent_id: str,
    sequence: int,
    user_message: str,
    assistant_response: str,
) -> str:
    digest = hashlib.sha256(b"contextdb-agent-turn-v1\0")
    for value in (session_id, agent_id):
        encoded = value.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    digest.update(sequence.to_bytes(8, "big"))
    for value in (user_message, assistant_response):
        encoded = value.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return f"agent-session:{session_id}:{sequence}:{digest.hexdigest()}"


class AgentSession:
    """Serial agent-loop helper over canonical observe/recall operations.

    It is orchestration only: the resolved ``RequestContext`` remains explicit,
    and it never treats context metadata as authentication.
    """

    def __init__(
        self,
        client: ContextDbClient,
        *,
        context: RequestContext,
        access: AccessPolicy,
        agent_id: str,
        session_id: str,
    ) -> None:
        if not agent_id or not session_id:
            raise ValueError("agent_id and session_id must be non-empty")
        if access.workspace_id != context.workspace_id:
            raise ValueError("access policy and request context workspace differ")
        self.client = client
        self.context = replace(
            context,
            audiences=frozenset(context.audiences),
            scopes=frozenset(context.scopes),
        )
        self.access = replace(
            access,
            scopes=frozenset(access.scopes),
            owners=frozenset(access.owners),
            audience=frozenset(access.audience),
            audience_purpose_grants=MappingProxyType(
                {key: frozenset(values) for key, values in access.audience_purpose_grants.items()}
            ),
            purposes=frozenset(access.purposes),
        )
        self.agent_id = agent_id
        self.session_id = session_id
        self._sequence = 0
        self._recall_sequence = 0
        self.last_trace: RecallTrace | None = None
        self.last_continuation: str | None = None
        self._lock = threading.Lock()

    def __enter__(self) -> AgentSession:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    @property
    def sequence(self) -> int:
        with self._lock:
            return self._sequence

    def before_turn(
        self,
        message: str,
        *,
        page_size: int = 20,
        at_commit: int | None = None,
        continuation: str | None = None,
    ) -> RecallResponse:
        with self._lock:
            return self._before_turn_unlocked(
                message,
                page_size=page_size,
                at_commit=at_commit,
                continuation=continuation,
            )

    def _before_turn_unlocked(
        self,
        message: str,
        *,
        page_size: int,
        at_commit: int | None,
        continuation: str | None,
    ) -> RecallResponse:
        request_context = self.context.with_request_id(
            f"session:{self.session_id}:before:{self._recall_sequence}"
        )
        response = self.client.recall(
            RecallRequest(
                context=request_context,
                query=message,
                page_size=page_size,
                at_commit=at_commit,
                continuation=continuation,
            )
        )
        self._recall_sequence += 1
        self.last_trace = response.trace
        self.last_continuation = response.continuation
        return response

    def after_turn(
        self,
        user_message: str,
        assistant_response: str,
        *,
        metadata: Mapping[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> ObserveResponse:
        with self._lock:
            return self._after_turn_unlocked(
                user_message,
                assistant_response,
                metadata=metadata,
                idempotency_key=idempotency_key,
            )

    def _after_turn_unlocked(
        self,
        user_message: str,
        assistant_response: str,
        *,
        metadata: Mapping[str, Any] | None,
        idempotency_key: str | None,
    ) -> ObserveResponse:
        content = {
            "kind": "chat_turn",
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "sequence": self._sequence,
            "user_message": user_message,
            "assistant_response": assistant_response,
        }
        wire_metadata = dict(metadata or {})
        wire_metadata.update(
            {
                "kind": "agent_session_turn",
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "sequence": self._sequence,
            }
        )
        response = self.client.observe(
            ObserveRequest(
                context=self.context.with_request_id(
                    f"session:{self.session_id}:after:{self._sequence}"
                ),
                idempotency_key=idempotency_key
                or _turn_key(
                    self.session_id,
                    self.agent_id,
                    self._sequence,
                    user_message,
                    assistant_response,
                ),
                observation_id=f"session:{self.session_id}:turn:{self._sequence}",
                metadata=wire_metadata,
                content=content,
                access=self.access,
            )
        )
        self._sequence += 1
        return response


class AsyncAgentSession:
    """Async variant of :class:`AgentSession`."""

    def __init__(
        self,
        client: AsyncContextDbClient,
        *,
        context: RequestContext,
        access: AccessPolicy,
        agent_id: str,
        session_id: str,
    ) -> None:
        self._sync = AgentSession(
            client.sync,
            context=context,
            access=access,
            agent_id=agent_id,
            session_id=session_id,
        )
        self.client = client
        self._lock = asyncio.Lock()

    @property
    def last_trace(self) -> RecallTrace | None:
        return self._sync.last_trace

    @property
    def last_continuation(self) -> str | None:
        return self._sync.last_continuation

    @property
    def sequence(self) -> int:
        return self._sync.sequence

    async def __aenter__(self) -> AsyncAgentSession:
        return self

    async def __aexit__(self, *_: object) -> None:
        return None

    async def before_turn(
        self,
        message: str,
        *,
        page_size: int = 20,
        at_commit: int | None = None,
        continuation: str | None = None,
    ) -> RecallResponse:
        async with self._lock:
            return await self._before_turn_unlocked(
                message,
                page_size=page_size,
                at_commit=at_commit,
                continuation=continuation,
            )

    async def _before_turn_unlocked(
        self,
        message: str,
        *,
        page_size: int,
        at_commit: int | None,
        continuation: str | None,
    ) -> RecallResponse:
        request_context = self._sync.context.with_request_id(
            f"session:{self._sync.session_id}:before:{self._sync._recall_sequence}"
        )
        response = await self.client.recall(
            RecallRequest(
                context=request_context,
                query=message,
                page_size=page_size,
                at_commit=at_commit,
                continuation=continuation,
            )
        )
        self._sync._recall_sequence += 1
        self._sync.last_trace = response.trace
        self._sync.last_continuation = response.continuation
        return response

    async def after_turn(
        self,
        user_message: str,
        assistant_response: str,
        *,
        metadata: Mapping[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> ObserveResponse:
        async with self._lock:
            return await self._after_turn_unlocked(
                user_message,
                assistant_response,
                metadata=metadata,
                idempotency_key=idempotency_key,
            )

    async def _after_turn_unlocked(
        self,
        user_message: str,
        assistant_response: str,
        *,
        metadata: Mapping[str, Any] | None,
        idempotency_key: str | None,
    ) -> ObserveResponse:
        sequence = self._sync.sequence
        content = {
            "kind": "chat_turn",
            "session_id": self._sync.session_id,
            "agent_id": self._sync.agent_id,
            "sequence": sequence,
            "user_message": user_message,
            "assistant_response": assistant_response,
        }
        wire_metadata = dict(metadata or {})
        wire_metadata.update(
            {
                "kind": "agent_session_turn",
                "session_id": self._sync.session_id,
                "agent_id": self._sync.agent_id,
                "sequence": sequence,
            }
        )
        response = await self.client.observe(
            ObserveRequest(
                context=self._sync.context.with_request_id(
                    f"session:{self._sync.session_id}:after:{sequence}"
                ),
                idempotency_key=idempotency_key
                or _turn_key(
                    self._sync.session_id,
                    self._sync.agent_id,
                    sequence,
                    user_message,
                    assistant_response,
                ),
                observation_id=f"session:{self._sync.session_id}:turn:{sequence}",
                metadata=wire_metadata,
                content=content,
                access=self._sync.access,
            )
        )
        self._sync._sequence += 1
        return response
