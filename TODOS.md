# TODOS

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
