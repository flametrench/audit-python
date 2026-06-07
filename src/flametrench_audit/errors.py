# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""AuditStore error taxonomy.

Error classes for spec PRs #43 (audit errors) and #46 (cursor/ordering
non-disclosure) will be added here once those PRs merge. For now only the
base class and NotFoundError are defined.
"""

from __future__ import annotations


class AuditError(Exception):
    """Base class for all flametrench-audit errors."""


class NotFoundError(AuditError):
    """Raised when a requested audit event does not exist."""
