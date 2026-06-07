# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""InMemoryAuditStore — spec-conformant in-memory AuditStore."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

from flametrench_ids import generate

from .errors import InvalidFormatError, NotFoundError
from .types import AuditContext, AuditEvent, AuthInfo, OnBehalf, Outcome, Scope, Target

_VALID_AUTH_KINDS = {"session", "pat", "share", "system"}
_AUTH_KIND_FIELD: dict[str, str] = {
    "session": "session_id",
    "pat": "pat_id",
    "share": "share_id",
    "system": "system_id",
}
_TARGET_KIND_RE = re.compile(r"^[a-z]{2,6}$")
_USR_ID_RE = re.compile(r"^usr_[0-9a-f]{32}$")
_VALID_OUTCOMES = frozenset(o.value for o in Outcome)
_MAX_EVENT_BYTES = 64 * 1024  # 64 KB per ADR 0019


def _validate_write(
    occurred_at: str,
    actor_usr_id: str | None,
    action: str,
    target: Target,
    outcome: Any,
    metadata: dict[str, Any],
    auth: AuthInfo | None,
    on_behalf: OnBehalf | None,
    scope: Scope | None,
    context: AuditContext | None,
) -> Outcome:
    """Validate write inputs; return coerced Outcome. Raises InvalidFormatError."""

    # outcome — accept Outcome enum or string; reject anything not in the set
    if isinstance(outcome, Outcome):
        coerced = outcome
    else:
        if str(outcome) not in _VALID_OUTCOMES:
            raise InvalidFormatError("outcome")
        coerced = Outcome(outcome)

    # actor_usr_id — null is valid (pre-auth / system); non-null must be usr_<32hex>
    if actor_usr_id is not None and not _USR_ID_RE.match(actor_usr_id):
        raise InvalidFormatError("actor_usr_id")

    # auth — if present, kind must be in frozen vocabulary, exactly one
    # kind-matching id field must be set, and no others
    if auth is not None:
        if auth.kind not in _VALID_AUTH_KINDS:
            raise InvalidFormatError("auth")
        expected = _AUTH_KIND_FIELD[auth.kind]
        all_ids = {
            "session_id": auth.session_id,
            "pat_id": auth.pat_id,
            "share_id": auth.share_id,
            "system_id": auth.system_id,
        }
        present = [k for k, v in all_ids.items() if v is not None]
        if len(present) != 1 or present[0] != expected:
            raise InvalidFormatError("auth")

    # target.kind — Flametrench entity type OR adopter object_type ^[a-z]{2,6}$
    # Both populations already satisfy the regex; any mismatch is invalid.
    if not _TARGET_KIND_RE.match(target.kind):
        raise InvalidFormatError("target.kind")

    # size — whole event (including metadata) MUST be ≤ 64 KB
    # Estimate via JSON serialization of the input fields (id/recorded_at are tiny)
    _size_probe: dict[str, Any] = {
        "occurred_at": occurred_at,
        "actor_usr_id": actor_usr_id,
        "action": action,
        "target": {"kind": target.kind, "id": target.id},
        "outcome": coerced.value,
        "metadata": metadata,
    }
    if auth is not None:
        _size_probe["auth"] = {"kind": auth.kind}
    if on_behalf is not None:
        _size_probe["on_behalf"] = {"agent_id": on_behalf.agent_id}
    if scope is not None:
        _size_probe["scope"] = {"kind": scope.kind, "id": scope.id}
    if context is not None:
        _size_probe["context"] = {}

    if len(json.dumps(_size_probe).encode()) > _MAX_EVENT_BYTES:
        raise InvalidFormatError("size")

    return coerced


class InMemoryAuditStore:
    """Append-only, in-memory AuditStore.

    All events are held in a dict keyed by ``aud_<32hex>`` wire id.
    Immutability is enforced: there is no update or delete path.
    ``write`` validates the event shape before storing (ADR 0019 §Errors).
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
        coerced_outcome = _validate_write(
            occurred_at, actor_usr_id, action, target, outcome,
            metadata, auth, on_behalf, scope, context,
        )
        aud_id = generate("aud")
        event = AuditEvent(
            id=aud_id,
            occurred_at=occurred_at,
            recorded_at=datetime.now(timezone.utc),
            actor_usr_id=actor_usr_id,
            action=action,
            target=target,
            outcome=coerced_outcome,
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
