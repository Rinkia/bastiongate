# Changelog

## 0.13.0 (unreleased)

- With `scrub_results`, secrets in text blobs (decoded, redacted, re-encoded) and in
  `resource_link` name/title/description are redacted too; URIs are also scanned
  percent-decoded (review follow-ups).
- **OpenTelemetry GenAI spans (T3).** `--otel-out FILE` (OTLP/JSON lines) and/or
  `--otel-endpoint URL` (OTLP/HTTP JSON, https or loopback http, headers from
  `OTEL_EXPORTER_OTLP_HEADERS`) emit one `execute_tool` span per `tools/call` with the gate's
  verdict (`bastion.gate.verdict|code|checks|tainted_egress`). Hashes by default;
  `--otel-content` adds PII-scrubbed, capped arguments and results. One trace per gate
  session. Stdlib only; export never blocks the proxy. Off by default.
- Security review (2026-10-03) fixes before release: odd JSON-RPC ids (lists, objects) and
  lone surrogates in tool names can no longer crash the response pump or the exporter;
  digests are keyed (HMAC) and taken after secret-key and PII redaction; secret-named
  argument fields are redacted in content; the endpoint refuses credentials, query and
  fragment, ignores proxy env vars and has a total POST deadline; bad OTLP headers fail at
  start; export failures print one WARN; the spans file is 0600; a server error is never
  labelled as a gate block.
- Evidence: live smoke, official MCP SDK 2.2.0 client through `bastiongate run --otel-out
  --otel-content` (a page tool returning an injection under warn, then `send_email`):
  `bastiontrace analyze --otel` on the gate's file reports LANDED (inject in `fetch_page`,
  landing on `send_email`), with the AWS key in the payload redacted in the file.

## 0.12.0 (unreleased)

- **Cross-server taint (E4), opt-in.** `taint_group: auto | <name>` (or env
  `BASTIONGATE_TAINT_GROUP`): the flow guard of every gate in the group also sees the
  others' untrusted and private reads, through a per-user SQLite store, so the trifecta
  that crosses MCP servers (fetch -> filesystem -> fetch) is caught. Rows name
  `server:tool` (server name from `initialize`); `tainted_egress` gains `cross_server`.
  `auto` = the spawning MCP client (POSIX process group; Windows nearest non-launcher
  ancestor). stdio only; off by default. Store errors fall back to local taint (one
  WARN, `taint_store_error`).
- Security review (2026-10-03) fixes before release: rows are one per source and capped per
  gate (no flood eviction of other gates' taint); a failed write is retried and a busy lock
  never disables sharing; live gates re-stamp their rows and stale rows (dead or idle
  gates) are ignored after 3 minutes; `auto` no longer treats a Python MCP client as a
  launcher; the env group name is validated; the state directory mode is set only when the
  gate creates it. Second round: a gate's own private flood can no longer evict its
  untrusted row (private overflow folds into one `server:*` row); no repeated writes for a
  source already stored; rows are re-stamped on activity even without the heartbeat
  thread; a busy read is retried once.
- Evidence: live smoke, official MCP SDK 2.2.0 client with two `bastiongate run` processes
  (fetch-like and filesystem-like servers): with `taint_group: auto` or a name, the egress
  fetch after a cross-server private read is blocked (-32005, `private_from:
  fssrv:read_file`); without a group it is forwarded, as before.

## 0.11.0 (unreleased)

- **BEHAVIOR: prompts and listings are checked** (`scan_prompts`, default true, per-prompt
  override under `prompts/get`).
  - `prompts/get`: hidden/control unicode, known bastioncorpus payloads and encoded known
    payloads only (templates are instructions by design). Blocks under the default
    `on_injected_result: block` (-32002).
  - `resources/list`, `resources/templates/list`, `prompts/list`: poisoned, oversize or
    malformed entries are dropped under `on_poisoned_tool: block`.
  - Uncorrelated responses of these shapes are routed to the same checks.
- Evidence: on 1,015 real skill and agent files, the prompt checks flagged no prompt (one hit:
  stray byte-order marks and a zero-width space in a CHANGELOG); the full signature set would
  have flagged 98.
- Security review (2026-10-03) fixes before release: an extra empty `messages`/listing key can
  no longer downgrade a tool result to the prompt checks; prompt descriptions without
  messages, prompt argument titles and variation-selector steganography are covered; known
  payloads match through look-alike letters, markdown emphasis and a dropped final period;
  ZWJ/ZWNJ in Indic and Arabic-script text no longer false-positive; prompts over 1M
  characters fail closed under block.
- Second review round: a `tools/list` or listing response that also carries `messages` or
  tool-result content gets the full result checks; ZWJ/ZWNJ are exempt only in scripts that
  spell with them (Indic, Arabic-script...), never between Cyrillic/Latin homoglyphs, and are
  removed before phrase matching.

## 0.10.0 (unreleased)

- **BEHAVIOR: resource content is scanned.** Embedded `resource` blocks (text, and text-MIME
  blobs decoded), `resource_link` name/title/description, and `resources/read` responses now
  go through the same result checks as text blocks: plain injection (-32002, blocks by
  default), encoded injection, PII scrub and flow-guard taint. Before 0.10 an injection in a
  resource reached the agent unscanned. Clean resources are forwarded unchanged. Kill switch:
  `scan_resources: false` (global or per tool; `resources/read` is the pseudo tool name for
  resource reads).
  - Blobs are decoded whatever their MIME type (a non-text type counts when it is valid
    UTF-8); media types (image, audio, video, font, PDF, zip) are never decoded, so a big
    image cannot trip the size fail-closed. Resource and link `uri`s are scanned too.
- **BEHAVIOR: upstream errors and uncorrelated responses are scanned.** The `message` and
  `data` of a JSON-RPC error answering a `tools/call` or `resources/read` go through the
  result checks (clients show them to the model). A response with no pending request (late
  past 5 minutes, duplicate or unknown id) is scanned as `(unmatched)` instead of passing
  through; an uncorrelated `tools/list` result is filtered. Found by the 2026-10-02 security
  review.
- tools/list scans now also read `title`, `annotations.title` and `outputSchema`, and the
  size cap counts the whole definition. Malformed (non-object) tool entries are dropped under
  `on_poisoned_tool: block`.
- **BEHAVIOR: `initialize` instructions are scanned.** Poisoned `instructions` are removed and a
  poisoned `serverInfo` is replaced (under `on_poisoned_tool: block`; `warn` only logs).
- A response the gate cannot inspect is replaced by error -32002 (`response_uninspectable`)
  instead of crashing the stdio pump. Secrets in upstream error messages are redacted with
  `scrub_results`. Both from the 2026-10-02 review, second round.
- **Encoded injection in tool results.** Results are decoded with bastioncorpus (base64,
  base32, hex, binary, ascii85/base85, Morse, percent and `\u` escapes) and scanned with
  bastionsupply's `encoded-injection` check.
  - New setting `on_encoded_result: warn | block`, **default `warn`** (shadow). Per-tool
    overrides work.
  - `warn` forwards the result, logs an `encoded_injection` trace event and a stderr WARN, and
    taints the session for the flow guard.
  - `block` returns error -32006.
  - A result over 1,000,000 characters is not decoded (event `encoded_scan_skipped`); under
    `block` it fails closed.
- **tools/list:** a tool definition hiding an encoded injection is warned about
  (`tools_list_encoded`), not dropped.
- **BEHAVIOR: oversize tool definitions fail closed.** A tool whose description plus input
  schema exceeds 1,000,000 characters is no longer scanned; it is handled like a poisoned tool
  (dropped under the default `on_poisoned_tool: block`, kept under `warn`), with the trace event
  `tools_list_oversize`. Before, the plain scan had no bound (about 7 s for a 20 MB definition).
  A page over 5,000,000 characters fails closed from the tool that crosses the limit.
- **`decode_transforms: true`** (opt-in, global or per tool) also scans the rot13 / leet /
  reversed / spaced-letter views of results up to 64 KB, under `on_encoded_result`. Off by
  default (more scan work per result); a bigger result logs `encoded_transforms_skipped`.
  Evidence: `bastionprobe encoding-bench --defenders supply,supply+transforms` (2026-10-02): rot13 1% -> 88%, leet 1% -> 76%, reversed 1% -> 88%, spaced letters 1% -> 8%, 0% benign FP; and 0 false positives on 45,025 real Markdown paragraphs (skills and memory notes). Promotion bar for a default
  of `true`: 20 real sessions with 0 false warnings.
- Decoding is faster with bastioncorpus 0.5.0's performance pass: the encoded scan of a 1 MB
  base64 result takes about 0.5 s (was 1.4 s).
- Plain injections keep their own path and code (-32002). Clean results are unchanged.
- Evidence (`bastionprobe encoding-bench`, 2026-10-01): bastionsupply's scan, which gate
  reuses, catches 88% of base64/hex/binary/base32/ascii85/base85/percent/escape-encoded
  corpus attacks (about 1% before), with 0% benign false positives.
- Requires bastionsupply >= 0.11.0. `bastionsupply doctor` warns when a v1 policy sets
  `on_encoded_result` but the installed gate is older than 0.10.

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
