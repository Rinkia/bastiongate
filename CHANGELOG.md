# Changelog

## 0.9.0

- **Flow guard (lethal trifecta).** A per-session taint record catches an egress
  call made after the session read both untrusted content and private data, even
  when every single call passes (the GitHub MCP toxic flow). Tools are labelled
  `untrusted` / `private` / `egress` from per-tool policy `labels`, built-in packs
  for common servers (github, filesystem, fetch, slack, gmail), then bastionsupply
  capability categories (auto labels only add `egress`). A GitHub same-repo rule
  keeps "fix issue #N" silent. New knobs: `scan_flows`, `on_tainted_egress`
  (`warn` | `block`, per-tool overridable), `label_packs`, per-tool `labels`.
- **BEHAVIOR:** the flow guard runs by default in **warn** (shadow) mode: it
  forwards the call, writes a `tainted_egress` trace event and prints one stderr
  line. `on_tainted_egress: block` returns JSON-RPC `-32005`. Promotion of the
  default to `block` needs the replay suite plus a dogfood run over >= 20 real
  sessions with 0 false blocks.
- **`bastiongate labels`** prints each tool's labels and where they came from.
- `python -m bastiongate.demo` replays the toxic flow (warn, then block).
- Metrics: `tainted_egress_warned`, `tainted_egress_blocked`, `labels_unavailable`,
  `taint_evicted`. Trace events: `tainted_egress`, `labels_unavailable`,
  `flow_guard_no_session` (session ids are hashed, content is never logged).
- Per-tool `labels` is validated in v1 files too (a string would otherwise be read
  one character at a time).
- Requires `bastionsupply>=0.9.0` (`capability_categories`).

### Upgrading

- Nothing blocks by default. Expect stderr warnings when a session reads untrusted
  and private content and then calls an egress tool; opt out with
  `scan_flows: false`, or tune per tool with `labels` / `on_tainted_egress`.
- Older gates silently ignore the new keys, even in v1 files: run
  `bastionsupply doctor --policy policy.yaml` (bastionsupply >= 0.9) to check.
- Next: cross-server taint (TODOS.md E4), runtime A2A gate (E2).

## 0.8.1

- **Fix:** `result_inspector: agentbastion` no longer writes `agentbastion.jsonl` into
  the gate's working directory. agentbastion's Firewall defaulted to its own event log,
  an unredacted second copy of flagged result text next to the gate's `--log` trace.
  The gate trace remains the single record. The file is also no longer tracked here.

## 0.8.0

- **`policy_version: 2`**: reads the suite's shared v2 policy format (the same file
  agentbastion reads). Gate knobs move under a strictly validated `gate:` block;
  typos, bad values, stray keys and v1-style top-level knobs in a v2 file stop the
  gate at startup instead of silently falling back to defaults. v1 files load
  exactly as before.
- **agentbastion kill switch in deep-inspect**: `detectors: {bastion.<id>: off |
  shadow | enforce}` is applied by `result_inspector: agentbastion` on every
  inspector branch (the heuristic-only branch previously built a bare Firewall and
  could not honor modes). Unknown IDs fail at startup with a did-you-mean hint;
  shadow hits are named in the gate trace.
- Gate's own checks have no detector IDs: the knobs are the modes (`scan_*: false`
  = off, `on_*: warn` = shadow). `gate.*` lines are rejected with that mapping.
- The `agentbastion` extras now require `agentbastion>=0.12.0`.
- A `detectors:` block without `policy_version: 2` raises instead of being ignored.
- `PolicyError` (a `ValueError`) is exported for callers that validate policies.

## 0.7.0

- The tools/list filter now drops tools flagged `homoglyph-name` by bastionsupply
  (a look-alike tool name impersonating another), alongside `tool-poisoning` and
  `hidden-unicode`. Requires bastionsupply >= 0.3.1.

## 0.6.0

- **structuredContent injection scan**: the result injection check now reads
  `structuredContent` (JSON results), not only text content blocks.
- **True-LRU session eviction**: the correlation session table evicts the
  least-recently-used session (was FIFO) under the `MAX_SESSIONS` backstop.
- **Embedder warmed at startup**: the semantic model loads and embeds its
  templates when the gate starts (bounded by `BASTIONGATE_EMBED_INIT_TIMEOUT`),
  so the first real result isn't stuck behind a cold load. `BASTIONGATE_EMBED_WARM=0`
  defers it. Air-gap: pre-cache the model + `HF_HUB_OFFLINE=1`.
- **Metrics**: `GET /__bastiongate/metrics` (auth-gated) returns block/redact/
  drop counters; stdio mode writes them to the trace at exit.

## 0.5.0

- **Local semantic embedder**: `inspector_semantic` can now use an in-process
  sentence-transformers model via `BASTIONGATE_EMBED_MODEL` — result text never
  leaves the process (closes the remote-embedder egress gap). The remote
  `BASTIONGATE_EMBED_URL` path remains; the local model wins when both are set.
  Install extra `bastiongateway[agentbastion-local]`.

## 0.4.0

Hardening pass over the 0.3.0 surface:

- **Result scrub now covers `structuredContent`** (JSON results), not just text
  blocks — both directions of PII scrub are now structure-aware.
- **Per-session correlation caps + idle TTL**: pending entries are bounded per
  session (not globally), so one busy/abusive session can't evict another's;
  orphaned entries expire; a session-count backstop bounds forged-id floods.
- **HTTP auth rate-limiting**: an IP is throttled with `429` after repeated
  failed `X-Bastiongate-Key` attempts.
- **Judge verdict cache**: the agentbastion judge path now uses a `TTLCache`
  (`BASTIONGATE_JUDGE_CACHE_TTL` / `_SIZE`) so repeat results skip the round-trip.

## 0.3.0

- **Per-tool policy overrides** (`tools:` map): scope `scrub_args`, `on_pii_arg`,
  `scan_results`, `on_injected_result`, `scrub_results`, `on_pii_result` per
  tool. Fixes the redact-mangles-`send_email`-recipient sharp edge. Policy files
  now parse with PyYAML (nested maps).
- **HTTP proxy auth** (`--auth-key` / `BASTIONGATE_PROXY_KEY`): require an
  `X-Bastiongate-Key` header, constant-time compared, never forwarded upstream.
- **Outbound result PII scrub** (`scrub_results`, `on_pii_result`): redact/block/
  warn on secrets a tool *returns* (opt-in; injection block still wins).
- **Semantic detector tier** for the agentbastion inspector (`inspector_semantic`
  + `BASTIONGATE_EMBED_URL`) — heuristics + semantic + judge now compose.
- **Session-scoped correlation**: request/response matching is keyed by
  `(Mcp-Session-Id, id)`, so one gate serving many HTTP sessions can't
  cross-correlate on a reused id. Pending-map is bounded.

## 0.2.0

- **HTTP/SSE transport** (`bastiongate run-http --upstream URL`): proxy MCP
  Streamable-HTTP servers, gating JSON and SSE responses. Binds 127.0.0.1,
  no-redirect + http/https-only opener (no SSRF via a malicious upstream),
  request body cap, forwarded-header safelist.
- **Argument PII/secret scrub** on `tools/call` (`scrub_args`, `on_pii_arg`):
  redact / block / warn on API keys, cloud tokens, private keys, JWTs, emails,
  SSNs, Luhn-valid card numbers. Only the kind is logged, never the value.
- **Deep result inspection** via agentbastion (`result_inspector: agentbastion`,
  optional `inspector_judge` LLM judge). Pluggable inspector seam with a
  fail-closed default.

## 0.1.0

- Initial release: stdio MCP proxy. Drops poisoned tools from `tools/list`,
  enforces a tool allow/deny policy, blocks injected tool-call results, JSONL
  trace. Reads bastionsupply `harden` policy files.
