# ARGUS — Single Source of Truth

**This file is the canonical status/roadmap pointer for BOTH repos:**
- `argus` (this repo, public, Apache-2.0) — the shipped SIEM
- `argus-sec` (private, closed) — the proprietary LLM layer, see its own `docs/STATUS.md`

Every other doc below is historical detail, not competing truth. If a doc disagrees
with this file, **this file wins** — go fix the doc, don't trust it standalone.
Update this file whenever status changes; it's a living index, not an archive.

---

## 1. Current state (as of 2026-07-02, commit `6fb4a08`)

| Fact | Value |
|---|---|
| Latest release | **v0.2.0** (tag `v0.2.0`, 2026-07-01) |
| License | Apache-2.0, public, `github.com/supermhel/argus` |
| Parsers shipped | 6: Linux SSH, Cisco ASA, Active Directory, VMware vSphere, generic syslog, Windows Event Log |
| Detection rules shipped | 5: brute-force, port-scan, lateral-movement, bank DB priv-esc, DC mass-VM-delete |
| Proven live | Full 7-workstream stack on real Docker/Redis/OpenSearch (not just zero-infra) — see build plan §"Docker — RESOLVED" |
| AI triage | Real Ollama integration + StubLLM fallback (`services/ws5-ai/llm_adapter.py::make_llm()`) |
| Open-core split | **Decided** (2026-07-01, via `/plan-ceo-review`): this repo stays fully open forever; ARGUS-Sec (trained model + regulatory compliance) is the paid, closed layer in a separate repo. No relicensing planned. |
| Bus backend | Redis Streams (real) + in-memory (tests). **Kafka is NOT implemented** despite older docs mentioning it as a "prod backend" — see architecture review §3 R-A. |
| Security posture | Stored-XSS in dashboard: **fixed** (`35f80fc`). Poison-message DLQ, input validation, prompt bounds: **fixed** (`a60e6d4`). No auth on any service (documented, accepted for v0.1/v0.2, see `SECURITY.md`). |

## 2. What's proven vs. what's still a claim

Read this before trusting any status word ("done", "proven", "resolved") in an older doc —
those words get reused loosely across specs written weeks apart.

- **Proven** = ran against real infra (real Redis, real Docker, a real adversarial subagent
  review with independent re-derivation) and the evidence is in a commit or a doc section
  with actual command output, not just a status label.
- **Design/claim** = written down as intent, not yet executed or verified. Treat as a plan,
  not a fact.

| Claim | Status | Evidence |
|---|---|---|
| Bus-only coupling (zero cross-workstream imports) | **Proven** | Grepped, zero hits — confirmed twice (this session + a subagent re-check) |
| WS-4 redelivery + DLQ on real Redis (XAUTOCLAIM/XPENDING) | **Proven** | Live-infra session, build plan §CI+live-infra |
| Deterministic `alert_id` (T7, dedup under redelivery) | **Proven** | `services/ws4-detection/main.py:52`, tested live |
| 3-tier edge/local/central deployment topology | **Design only** | `2026-06-27-argus-production-roadmap-design.md` — nothing built |
| Kafka as central-tier bus | **Design only, contradicted by code** | No `_KafkaBus` exists; docstring now corrected |
| Rule matching scales past ~50 rules | **Known gap, not fixed** | O(rules×events) linear scan, no class_uid pre-filter — flagged in architecture review §4 |
| Open-core split (this repo free / argus-sec paid) | **Decided, not yet legally documented** | Decision made 2026-07-01; LICENSE/README don't yet state it explicitly (see §4 below) |

## 3. Doc index — what each file is for, and its trust level

**Read `SSOT.md` (this file) first. Then only open a doc below if you need its specific detail.**

| File | Purpose | Trust level |
|---|---|---|
| `README.md` | Public-facing intro | Current |
| `CHANGELOG.md` | Version history | Current, authoritative for "what shipped when" |
| `SECURITY.md` | Threat boundary | Current |
| `CONTRIBUTING.md` | How to add a parser/rule | Current |
| `contracts/*.md` (bus-topics, ocsf-classes, sigma-convention) | Frozen Phase-0 contracts (A/B/D) | Current — these are the schema source of truth, don't restate them elsewhere |
| `docs/PHASE0_README.md`, `docs/INTERFACE.template.md` | Historical Phase-0 process docs | Historical, still accurate for what they describe |
| `docs/adding-a-parser.md` | Contributor walkthrough | Current |
| `services/*/INTERFACE.md` (7 files) | Per-workstream contract | **Partially stale** — e.g. ws2's lists 3 parsers, repo now ships 6; ws5's/ws1's predate the real Ollama/syslog-UDP work. Treat as "what WS-N's *contract* is", not "what's implemented" — cross-check against the actual `services/wsN/` code. |
| `docs/superpowers/specs/2026-06-27-argus-v0.1-build-plan.md` | v0.1 execution record | Historical — DONE, superseded by v0.2 but factually accurate for its era |
| `docs/superpowers/specs/2026-06-27-argus-production-roadmap-design.md` | 3-tier production vision + §9 open-core design | **Design/aspiration, not built** — don't read as current architecture |
| `docs/superpowers/specs/2026-06-28-T3-loop-ownership-decision.md` | Bus/runner design decision | Historical, now annotated RESOLVED (was marked unproven; gaps closed since — see file header) |
| `docs/superpowers/specs/2026-07-02-argus-architecture-review.md` | Cross-cutting architecture review (v0.2, current) | **Current** — the most up-to-date structural analysis; adversarially reviewed, claims confirmed against code |
| `docs/superpowers/specs/2026-07-02-argus-v0.3-improvement-plan.md` | v0.3 plan: more rules, robust rule logic, the rule-prefilter architecture fix, triage-first dashboard | **Current** — the forward roadmap; nothing built yet, this is the plan |
| `docs/posts/launch-drafts.md` | Marketing draft | Draft, not published |
| `AGENTS.md` | Imported cowork stub | Minimal, ignore |

## 4. Known doc debt (don't fix silently, flag before touching)

- **`services/ws2-normalization/INTERFACE.md`** says "3 parsers"; code has 6. Needs an update
  pass, low urgency (contributors read `docs/adding-a-parser.md`, not this file, for onboarding).
- **Open-core decision isn't yet reflected in `README.md`/`LICENSE`/`SECURITY.md`.** The
  decision (§2 above) is real and made, but nothing in the public-facing docs *says* "this
  repo is free forever, there's a paid layer elsewhere." Worth a short README section once
  the ARGUS-Sec product is closer to real (no rush — premature to advertise a product that's
  still Wave 0 corpus/tooling prep).
- **Production roadmap doc (`2026-06-27-...-design.md`) reads confidently** ("3-tier",
  "edge agents") but is 100% unbuilt design. A future reader skimming only that file would
  overestimate what exists. This SSOT file is the correction.

---

*Update this file, don't create a new status doc, whenever a fact in §1/§2 changes. If a
new spec doc is added under `docs/superpowers/specs/`, add one line to §3 immediately.*
