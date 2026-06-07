# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""AuditStore error taxonomy (locked by spec PRs #43 and #46).

Cross-cutting taxonomy (mirrors identity, tenancy, authorization):
- ``InvalidFormatError`` — shape/value violation; carries a ``field``
  discriminator naming the offending part of the event.
- ``PreconditionError`` — system-state precondition failed (e.g. writing
  to a revoked scope when a store enforces it).
- ``NotFoundError`` — requested event does not exist.

Opacity is preserved: ``action``, ``on_behalf.agent_id``, ``auth.system_id``,
and adopter ``target.id`` are NEVER validated and NEVER raise ``InvalidFormatError``.
"""

from __future__ import annotations


class AuditError(Exception):
    """Base class for all flametrench-audit errors."""


class InvalidFormatError(AuditError):
    """A field value violates the AuditEvent shape contract (ADR 0019 §Errors).

    ``field`` names the offending part of the event:
    - ``"auth"``        — zero, multiple, or mismatched auth kind/id fields
    - ``"size"``        — event exceeds 64 KB
    - ``"outcome"``     — value outside {success, failure, denied, pending}
    - ``"actor_usr_id"`` — non-null but not a valid usr_<32hex>
    - ``"target.kind"`` — matches neither a Flametrench entity type nor ^[a-z]{2,6}$
    """

    def __init__(self, field: str, message: str = "") -> None:
        self.field = field
        super().__init__(message or f"Invalid value for field: {field!r}")


class PreconditionError(AuditError):
    """A system-state precondition for the operation was not met."""


class NotFoundError(AuditError):
    """Raised when a requested audit event does not exist."""
