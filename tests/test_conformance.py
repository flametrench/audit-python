# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""Flametrench v0.4 conformance suite — Python harness for audit.

Implements the state-machine fixture format. Each test:

1. Pre-allocates fresh usr_ IDs for declared named users.
2. Creates a fresh InMemoryAuditStore.
3. Walks the steps list, resolving {var} references from the variable map.

Matching for ``get`` results is SUPERSET (result ⊇ expected): the expected
object lists the fields whose values ADR 0019 pins; server-set fields
(``recorded_at``) are not asserted here.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
from flametrench_ids import generate

from flametrench_audit import (
    AuditContext,
    AuditEvent,
    AuthInfo,
    InMemoryAuditStore,
    NotFoundError,
    OnBehalf,
    Outcome,
    Scope,
    Target,
)

_FIXTURES_DIR = Path(__file__).parent / "conformance" / "fixtures"
_VAR_PATTERN = re.compile(r"^\{([a-z_][a-z0-9_]*)\}$")

_ERROR_CLASSES: dict[str, type[Exception]] = {
    "NotFoundError": NotFoundError,
}


def _load_fixture(relative_path: str) -> dict[str, Any]:
    return json.loads((_FIXTURES_DIR / relative_path).read_text(encoding="utf-8"))


def _resolve(value: Any, variables: dict[str, Any]) -> Any:
    if isinstance(value, str):
        match = _VAR_PATTERN.match(value)
        if match:
            name = match.group(1)
            if name not in variables:
                raise KeyError(f"Unknown variable in fixture: {{{name}}}")
            return variables[name]
        return value
    if isinstance(value, list):
        return [_resolve(v, variables) for v in value]
    if isinstance(value, dict):
        return {k: _resolve(v, variables) for k, v in value.items()}
    return value


def _walk_path(obj: Any, dotted_path: str) -> Any:
    current = obj
    for segment in dotted_path.split("."):
        if hasattr(current, segment):
            current = getattr(current, segment)
        elif isinstance(current, dict) and segment in current:
            current = current[segment]
        else:
            raise KeyError(
                f"Cannot resolve path segment '{segment}' on {type(current).__name__}"
            )
    return current


def _parse_auth(raw: dict[str, Any] | None) -> AuthInfo | None:
    if raw is None:
        return None
    return AuthInfo(
        kind=raw["kind"],
        session_id=raw.get("session_id"),
        pat_id=raw.get("pat_id"),
        share_id=raw.get("share_id"),
        system_id=raw.get("system_id"),
    )


def _parse_context(raw: dict[str, Any] | None) -> AuditContext | None:
    if raw is None:
        return None
    return AuditContext(
        request_id=raw.get("request_id"),
        ip=raw.get("ip"),
        user_agent=raw.get("user_agent"),
    )


def _event_to_dict(event: AuditEvent) -> dict[str, Any]:
    """Convert AuditEvent to a dict for superset matching."""
    d: dict[str, Any] = {
        "id": event.id,
        "occurred_at": event.occurred_at,
        "actor_usr_id": event.actor_usr_id,
        "action": event.action,
        "target": {"kind": event.target.kind, "id": event.target.id},
        "outcome": event.outcome.value,
        "metadata": event.metadata,
    }
    if event.auth is not None:
        auth_d: dict[str, Any] = {"kind": event.auth.kind}
        if event.auth.session_id is not None:
            auth_d["session_id"] = event.auth.session_id
        if event.auth.pat_id is not None:
            auth_d["pat_id"] = event.auth.pat_id
        if event.auth.share_id is not None:
            auth_d["share_id"] = event.auth.share_id
        if event.auth.system_id is not None:
            auth_d["system_id"] = event.auth.system_id
        d["auth"] = auth_d
    if event.on_behalf is not None:
        d["on_behalf"] = {"agent_id": event.on_behalf.agent_id}
    if event.scope is not None:
        d["scope"] = {"kind": event.scope.kind, "id": event.scope.id}
    if event.context is not None:
        ctx_d: dict[str, Any] = {}
        if event.context.request_id is not None:
            ctx_d["request_id"] = event.context.request_id
        if event.context.ip is not None:
            ctx_d["ip"] = event.context.ip
        if event.context.user_agent is not None:
            ctx_d["user_agent"] = event.context.user_agent
        if ctx_d:
            d["context"] = ctx_d
    return d


def _assert_superset(actual: Any, expected: Any, path: str = "") -> None:
    """Assert actual ⊇ expected (recursive subset match)."""
    if isinstance(expected, dict):
        assert isinstance(actual, dict), (
            f"at {path!r}: expected dict, got {type(actual).__name__}"
        )
        for key, exp_val in expected.items():
            assert key in actual, f"at {path!r}: missing key {key!r}"
            _assert_superset(actual[key], exp_val, f"{path}.{key}" if path else key)
    else:
        assert actual == expected, (
            f"at {path!r}: expected {expected!r}, got {actual!r}"
        )


def _invoke_op(store: InMemoryAuditStore, op: str, args: dict[str, Any]) -> Any:
    if op == "write":
        return store.write(
            occurred_at=args["occurred_at"],
            actor_usr_id=args.get("actor_usr_id"),
            action=args["action"],
            target=Target(kind=args["target"]["kind"], id=args["target"]["id"]),
            outcome=Outcome(args["outcome"]),
            metadata=args.get("metadata", {}),
            auth=_parse_auth(args.get("auth")),
            on_behalf=(
                OnBehalf(agent_id=args["on_behalf"]["agent_id"])
                if args.get("on_behalf") else None
            ),
            scope=(
                Scope(kind=args["scope"]["kind"], id=args["scope"]["id"])
                if args.get("scope") else None
            ),
            context=_parse_context(args.get("context")),
        )

    if op == "get":
        return store.get(args["id"])

    raise RuntimeError(f"Unknown fixture op: {op!r}")


def _run_test(test: dict[str, Any]) -> None:
    store = InMemoryAuditStore()
    variables: dict[str, Any] = {
        name: generate("usr") for name in test.get("users", [])
    }

    for step in test["steps"]:
        op = step["op"]
        resolved_input = _resolve(step["input"], variables)

        expected = step.get("expected")
        if expected and "error" in expected:
            error_class = _ERROR_CLASSES[expected["error"]]
            with pytest.raises(error_class):
                _invoke_op(store, op, resolved_input)
            return

        result = _invoke_op(store, op, resolved_input)

        if expected and "result" in expected:
            resolved_spec = _resolve(expected["result"], variables)
            actual_dict = _event_to_dict(result)
            _assert_superset(actual_dict, resolved_spec)

        captures = step.get("captures")
        if captures:
            for name, path in captures.items():
                variables[name] = _walk_path(result, path)


def _collect_tests(relative_path: str) -> list[Any]:
    fixture = _load_fixture(relative_path)
    return [pytest.param(t, id=t["id"]) for t in fixture["tests"]]


# ─── audit.write — event shape (ADR 0019) ───


@pytest.mark.parametrize("test_case", _collect_tests("audit/write-event-shape.json"))
def test_write_event_shape_conformance(test_case: dict[str, Any]) -> None:
    _run_test(test_case)
