# Changelog

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
