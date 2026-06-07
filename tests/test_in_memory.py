# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for InMemoryAuditStore."""

from __future__ import annotations

from datetime import datetime, timezone

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


def _store() -> InMemoryAuditStore:
    return InMemoryAuditStore()


def _write_minimal(store: InMemoryAuditStore, **kwargs: object) -> AuditEvent:
    defaults: dict[str, object] = {
        "occurred_at": "2026-06-07T00:00:00.000Z",
        "actor_usr_id": None,
        "action": "test.action",
        "target": Target(kind="doc", id="doc_deadbeef" * 2 + "00000000"),
        "outcome": Outcome.SUCCESS,
        "metadata": {},
    }
    defaults.update(kwargs)
    return store.write(**defaults)  # type: ignore[arg-type]


class TestWrite:
    def test_returns_event_with_aud_id(self):
        store = _store()
        event = _write_minimal(store)
        assert event.id.startswith("aud_")
        assert len(event.id) == 36  # aud_ + 32 hex

    def test_server_sets_recorded_at(self):
        before = datetime.now(timezone.utc)
        store = _store()
        event = _write_minimal(store)
        after = datetime.now(timezone.utc)
        assert before <= event.recorded_at <= after

    def test_occurred_at_stored_verbatim(self):
        store = _store()
        ts = "2026-06-05T10:00:00.000Z"
        event = store.write(
            occurred_at=ts,
            actor_usr_id=None,
            action="a.b",
            target=Target(kind="doc", id="x"),
            outcome=Outcome.SUCCESS,
            metadata={},
        )
        assert event.occurred_at == ts

    def test_actor_usr_id_null_accepted(self):
        store = _store()
        event = _write_minimal(store, actor_usr_id=None)
        assert event.actor_usr_id is None

    def test_actor_usr_id_wire_id_accepted(self):
        usr_id = generate("usr")
        store = _store()
        event = _write_minimal(store, actor_usr_id=usr_id)
        assert event.actor_usr_id == usr_id

    def test_each_write_unique_id(self):
        store = _store()
        ids = {_write_minimal(store).id for _ in range(5)}
        assert len(ids) == 5

    def test_outcome_enum_preserved(self):
        store = _store()
        for outcome in Outcome:
            event = store.write(
                occurred_at="2026-06-07T00:00:00.000Z",
                actor_usr_id=None,
                action="a.b",
                target=Target(kind="doc", id="x"),
                outcome=outcome,
                metadata={},
            )
            assert event.outcome == outcome

    def test_auth_pat_stored(self):
        store = _store()
        auth = AuthInfo(kind="pat", pat_id="pat_" + "0" * 32)
        event = _write_minimal(store, actor_usr_id=generate("usr"), auth=auth)
        assert event.auth is not None
        assert event.auth.kind == "pat"
        assert event.auth.pat_id == auth.pat_id

    def test_auth_system_stored(self):
        store = _store()
        auth = AuthInfo(kind="system", system_id="billing-cron")
        event = _write_minimal(store, auth=auth)
        assert event.auth is not None
        assert event.auth.kind == "system"
        assert event.auth.system_id == "billing-cron"

    def test_on_behalf_stored(self):
        store = _store()
        ob = OnBehalf(agent_id="agent-x")
        event = _write_minimal(store, on_behalf=ob)
        assert event.on_behalf is not None
        assert event.on_behalf.agent_id == "agent-x"

    def test_scope_stored(self):
        store = _store()
        org_id = generate("org")
        scope = Scope(kind="org", id=org_id)
        event = _write_minimal(store, scope=scope)
        assert event.scope is not None
        assert event.scope.kind == "org"
        assert event.scope.id == org_id

    def test_context_stored(self):
        store = _store()
        ctx = AuditContext(request_id="req-1", ip="10.0.0.1")
        event = _write_minimal(store, context=ctx)
        assert event.context is not None
        assert event.context.request_id == "req-1"
        assert event.context.ip == "10.0.0.1"

    def test_optional_fields_absent_by_default(self):
        store = _store()
        event = _write_minimal(store)
        assert event.auth is None
        assert event.on_behalf is None
        assert event.scope is None
        assert event.context is None

    def test_metadata_stored_verbatim(self):
        store = _store()
        meta = {"mcp": True, "nested": {"x": 1}}
        event = store.write(
            occurred_at="2026-06-07T00:00:00.000Z",
            actor_usr_id=None,
            action="a.b",
            target=Target(kind="doc", id="x"),
            outcome=Outcome.SUCCESS,
            metadata=meta,
        )
        assert event.metadata == meta

    def test_event_is_immutable(self):
        store = _store()
        event = _write_minimal(store)
        with pytest.raises((TypeError, AttributeError)):
            event.action = "mutated"  # type: ignore[misc]


class TestGet:
    def test_get_returns_stored_event(self):
        store = _store()
        written = _write_minimal(store)
        fetched = store.get(written.id)
        assert fetched.id == written.id
        assert fetched.action == written.action

    def test_get_unknown_raises_not_found(self):
        store = _store()
        with pytest.raises(NotFoundError):
            store.get(generate("aud"))

    def test_get_preserves_all_optional_fields(self):
        store = _store()
        usr_id = generate("usr")
        org_id = generate("org")
        written = store.write(
            occurred_at="2026-06-07T12:00:00.000Z",
            actor_usr_id=usr_id,
            action="data.create.record",
            target=Target(kind="doc", id="doc_abc"),
            outcome=Outcome.SUCCESS,
            metadata={"mcp": True},
            auth=AuthInfo(kind="session", session_id="ses_" + "0" * 32),
            on_behalf=OnBehalf(agent_id="agent-42"),
            scope=Scope(kind="org", id=org_id),
            context=AuditContext(ip="127.0.0.1"),
        )
        fetched = store.get(written.id)
        assert fetched.auth is not None and fetched.auth.kind == "session"
        assert fetched.on_behalf is not None and fetched.on_behalf.agent_id == "agent-42"
        assert fetched.scope is not None and fetched.scope.id == org_id
        assert fetched.context is not None and fetched.context.ip == "127.0.0.1"
