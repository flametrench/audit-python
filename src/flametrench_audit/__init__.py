# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""flametrench-audit — append-only, identity- and tenancy-aware audit events.

The spec-normative audit layer for Flametrench v0.4. See the upstream
specification at https://github.com/flametrench/spec/blob/main/decisions/0019-audit-primitive.md.

Every AuditEvent is immutable once written. The store exposes no update or
delete operations; implementations MUST be durable before returning from write.
"""

from .errors import AuditError, NotFoundError
from .in_memory import InMemoryAuditStore
from .store import AuditStore
from .types import (
    AuditContext,
    AuditEvent,
    AuthInfo,
    OnBehalf,
    Outcome,
    Scope,
    Target,
)

__all__ = [
    "AuditContext",
    "AuditError",
    "AuditEvent",
    "AuditStore",
    "AuthInfo",
    "InMemoryAuditStore",
    "NotFoundError",
    "OnBehalf",
    "Outcome",
    "Scope",
    "Target",
]

__version__ = "0.4.0"
