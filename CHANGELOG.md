# Changelog

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
