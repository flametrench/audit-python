# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""InMemoryAuditStore — spec-conformant in-memory AuditStore."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from flametrench_ids import generate

from .errors import NotFoundError
from .types import AuditContext, AuditEvent, AuthInfo, OnBehalf, Outcome, Scope, Target


class InMemoryAuditStore:
    """Append-only, in-memory AuditStore.

    All events are held in a dict keyed by ``aud_<32hex>`` wire id.
    Immutability is enforced: there is no update or delete path.
    """

    def __init__(self) -> None:
        self._events: dict[str, AuditEvent] = {}

    def write(
        self,
        *,
        occurred_at: str,
        actor_usr_id: str | None,
        action: str,
        target: Target,
        outcome: Outcome,
        metadata: dict[str, Any],
        auth: AuthInfo | None = None,
        on_behalf: OnBehalf | None = None,
        scope: Scope | None = None,
        context: AuditContext | None = None,
    ) -> AuditEvent:
        aud_id = generate("aud")
        event = AuditEvent(
            id=aud_id,
            occurred_at=occurred_at,
            recorded_at=datetime.now(timezone.utc),
            actor_usr_id=actor_usr_id,
            action=action,
            target=target,
            outcome=outcome,
            metadata=metadata,
            auth=auth,
            on_behalf=on_behalf,
            scope=scope,
            context=context,
        )
        self._events[aud_id] = event
        return event

    def get(self, aud_id: str) -> AuditEvent:
        event = self._events.get(aud_id)
        if event is None:
            raise NotFoundError(f"Audit event not found: {aud_id!r}")
        return event
