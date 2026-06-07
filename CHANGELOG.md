# Changelog

All notable changes to `flametrench-audit` are recorded here.
Spec-level changes live in [`spec/CHANGELOG.md`](https://github.com/flametrench/spec/blob/main/CHANGELOG.md).

## [v0.4.0] — 2026-06-07

### Added
- Initial release: `AuditStore` Protocol, `InMemoryAuditStore`, and the full `AuditEvent` shape ([ADR 0019](https://github.com/flametrench/spec/blob/main/decisions/0019-audit-primitive.md)).
  - `write` — durable append of an event; returns the stored `AuditEvent` with server-set `id` and `recorded_at`.
  - `get` — fetch a single event by `aud_<32hex>` wire id; raises `NotFoundError` for unknown ids.
  - All optional axes preserved verbatim: `auth` (session/pat/share/system kinds per ADR 0016), `on_behalf` (delegated agent), `scope` (tenancy boundary), `context` (request metadata).
  - `actor_usr_id: null` supported for pre-authentication and system-actor events.
  - 7 conformance tests from `spec/conformance/fixtures/audit/write-event-shape.json` — all green.
