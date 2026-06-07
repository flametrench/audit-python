# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""AuditStore — every audit backend implements this contract.

Atomicity guarantees per ADR 0019:
- ``write`` MUST be durable before it returns. Audit is fail-closed.
- Events are immutable once written; no ``update`` or ``delete`` exists.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from .types import AuditContext, AuditEvent, AuthInfo, OnBehalf, Outcome, Scope, Target


@runtime_checkable
class AuditStore(Protocol):
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
        """Append an event; synchronous and durable before return.

        ``id`` and ``recorded_at`` are set by the store; callers MUST NOT
        supply them. Returns the stored event with those fields populated.
        """
        ...

    def get(self, aud_id: str) -> AuditEvent:
        """Fetch an event by wire-format id. Raises NotFoundError if absent."""
        ...
