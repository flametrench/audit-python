# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""AuditEvent shape and supporting types (ADR 0019)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any


class Outcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"
    PENDING = "pending"


@dataclass(frozen=True)
class AuthInfo:
    """auth block — present IFF an established principal exists (ADR 0019).

    Exactly one of session_id / pat_id / share_id / system_id is set and
    matches `kind`. All four values come from ADR 0016's frozen vocabulary.
    """
    kind: str
    session_id: str | None = None
    pat_id: str | None = None
    share_id: str | None = None
    system_id: str | None = None


@dataclass(frozen=True)
class OnBehalf:
    """Delegated non-human actor (ADR 0019 §on_behalf).

    Orthogonal to auth.kind — an agent uses a session or PAT credential
    and is additionally identified here by an opaque adopter-defined string.
    """
    agent_id: str


@dataclass(frozen=True)
class Target:
    kind: str
    id: str


@dataclass(frozen=True)
class Scope:
    kind: str
    id: str


@dataclass(frozen=True)
class AuditContext:
    request_id: str | None = None
    ip: str | None = None
    user_agent: str | None = None


@dataclass(frozen=True)
class AuditEvent:
    """An immutable audit event as stored and returned by AuditStore.

    ``id`` and ``recorded_at`` are set by the store on ``write``;
    emitters MUST NOT supply them. ``occurred_at`` is the emitter's clock
    and is stored verbatim (no normalisation) to guarantee round-trip fidelity.
    """
    id: str
    occurred_at: str
    recorded_at: datetime
    actor_usr_id: str | None
    action: str
    target: Target
    outcome: Outcome
    metadata: dict[str, Any]
    auth: AuthInfo | None = None
    on_behalf: OnBehalf | None = None
    scope: Scope | None = None
    context: AuditContext | None = None
