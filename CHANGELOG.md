# Changelog

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
