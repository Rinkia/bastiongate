# TODOS

## Open

### Whole-text decode views in the runtime scanners

**What:** run the rot13 / leet / reversed / spaced-letter views (`bastioncorpus.variants(text, transforms=True)`) on tool results in the gate and on replies in bastionmesh, not only in agentbastion's input guard.

**Why:** v0.10 decodes encoded runs only (base64, hex, binary...), so a rot13 or reversed payload planted in a web page passes the gate. encoding-bench (2026-10-01): supply/gate catch about 1% of rot13/leet/reversed rows, against 88% for the run-based encodings.

**Context:** deferred by D3 of the encoded-payload eng review (`bastion-decode-DESIGN.md`): whole-text views multiply the scan work on every result and add false-positive surface. Decide with encoding-bench numbers on cost per result, extra catches and benign FP rate. Start in `guards.scan_encoded_text`.

**Effort:** S
**Priority:** P3
**Depends on:** bastioncorpus 0.5 + bastionprobe encoding-bench (both done).

### E2: runtime A2A gate (bastionmesh)

**Status (2026-09-30):** moved to its own tool, [github.com/Rinkia/bastionmesh](https://github.com/Rinkia/bastionmesh) (v0.1.0 built, not yet on PyPI). Its follow-ups live in bastionmesh/TODOS.md. Kept here for history.

**What:** Proxy A2A JSON-RPC (`message/send`, `tasks/*`) the way bastiongate proxies MCP: scan message parts for injection, apply allow/deny per peer agent, cap delegation depth and fan-out.

**Why:** The L5 plan (2026-09-29) covers A2A cards statically (bastionsupply) and multi-agent runs forensically (bastiontrace), but nothing enforces inline between agents (OWASP ASI07/ASI08).

**Context:** Plan and review: `~/.gstack/projects/Varie/stefano-agentic-l5-plan-20260929-autoplan.md`. Reuse the flow-guard labels and taint semantics from gate 0.9.

**Effort:** L
**Priority:** P2
**Depends on:** gate 0.9.0 flow guard.

### E4: cross-server taint

**What:** Share flow-guard taint across gate processes, so a chain that reads a secret through server A and sends it out through server B is caught. Two options: a local shared store, or one gate fronting multiple upstreams.

**Why:** Gate 0.9 taint is per session, per upstream server. The common trifecta (filesystem server + fetch server) crosses servers and passes today. This is the documented critical gap in the L5 plan's failure registry.

**Effort:** L
**Priority:** P2
**Depends on:** gate 0.9.0.

### T3: gate as an OTel GenAI span producer

**What:** Emit `execute_tool` spans with hashed content plus verdict attributes, so gate plugs into existing observability stacks and bastiontrace gets traces the suite guarantees exist.

**Why:** Outside-voice 10x reframe in the L5 review. Most OTel exports lack content, and gate can produce reliable traces itself.

**Effort:** M
**Priority:** P3


## Completed

### A2 follow-ups outside this repo (done)

**What:** `bastionsupply doctor --policy <file>` warns when a policy_version 2 file meets agentbastion < 0.12 or bastiongate < 0.8 (which ignore `detectors:` / the `gate:` block); the v2 contract is documented in `bastioncorpus/CONTRACTS.md`.

**Shipped:** bastionsupply 0.7.0 (Rinkia/bastionsupply#8) and Rinkia/bastioncorpus#10. Remaining gap: no producer lock until `harden` emits v2.

### A2: adopt policy v2 + detector modes in bastiongate (done in 0.8.0)

**What:** Teach bastiongate the v2 policy format: a v2 loader, gate knobs under a `gate:` block, `gate.*` detector IDs, and kill-switch/shadow support for `bastion.*` detectors through deep-inspect.

**Why:** agentbastion 0.12 (A1) ships the detector kill switch. Until gate adopts v2, gate's agentbastion deep-inspect can't honor it, and gate's own detections (poisoned tool, injected result, PII) can't be shadowed or switched off.

**Context:** This is the second half of the eng-review split (decision D2). Full design and decisions: `~/.gstack/projects/Varie/stefano-bastion-release-design-20260927-232415.md` ("Eng Review Decisions" + "Outside-voice decisions"). Scope:
- v2 loader: frozen shared core + `gate:` block, strict validation, `default:` required only with tool-policy keys (OV1), raise on `default: allow` + non-empty allow list (OV2).
- `integrations/agentbastion.py:42-43` `build_inspector`: always build `Firewall(inbound=InboundGuard(modes=...))` (today it's a bare `Firewall()` in the heuristic-only branch).
- Raise if `bastion.*` entries are present while `result_inspector != agentbastion`.
- Validate `bastion.*` IDs by importing `agentbastion.registry` (no copied list); bump the extras floor to `agentbastion>=0.12`.
- Register gate's own detections as `gate.*` IDs (design Open Question 3).
- `bastionsupply doctor --policy <file>`: warn when a v2 file meets a consumer below the floor (design D-A1).
- `bastioncorpus/CONTRACTS.md` + policy_v2 golden producer/consumer locks.
Separate but related: the v1 implicit-default divergence (gate `allow` vs agentbastion `deny`) is its own warn-first BREAKING task.

**Effort:** M
**Priority:** P1
**Depends on:** agentbastion 0.12.0 (A1) released to PyPI.

**Completed:** 0.8.0 (2026-09-28). Scope change (design decision A): gate got **no** `gate.*` detector IDs; its knobs already are the modes (`scan_*: false` = off, `on_*: warn` = shadow) and `gate.*` lines are rejected. doctor --policy and CONTRACTS.md moved to the follow-up above.
