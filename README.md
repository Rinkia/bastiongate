# bastiongate

**MCP security gateway.** An inline proxy that sits between an AI agent and its
MCP servers and enforces security on every call:

- **scans `tools/list`** and drops tools whose definitions carry prompt
  injection or hidden unicode (via [bastionsupply](https://github.com/Rinkia/bastionsupply))
- **enforces a tool allow/deny policy** — the agent can only call what you permit
- **scans tool-call results** and blocks any that carry indirect prompt
  injection before the agent ever reads them
- **logs every message** as a JSONL trace for forensics

The runtime-enforcement leg of the **bastion family**:

| tool | job |
|------|-----|
| **bastiongate** | **gate** — enforce security inline on live MCP traffic |
| [bastionsupply](https://github.com/Rinkia/bastionsupply) | scan an MCP server before you trust it |
| [agentbastion](https://github.com/Rinkia/agentbastion) | prevent — firewall around a running agent |
| [bastionprobe](https://github.com/Rinkia/bastionprobe) | attack — pentest your agent with injections |
| [bastiontrace](https://github.com/Rinkia/bastiontrace) | investigate — forensics on an agent trace |

## Install

```bash
pip install bastiongateway
```

(The PyPI distribution is `bastiongateway`; the import package and `bastiongate`
CLI keep that name.)

## Use

The gate *is* an MCP server to your agent, and a client to the real one. Point
your MCP client's `command` at the gate and put the real server after `--`:

```jsonc
// mcp.json
{
  "mcpServers": {
    "docs": {
      "command": "bastiongate",
      "args": ["run", "--policy", "policy.yaml", "--log", "gate.jsonl",
               "--", "npx", "-y", "@some/mcp-server"]
    }
  }
}
```

Everything the agent sends flows through the gate to the server and back, with
the checks applied in between.

### Policy

Drop in the same YAML `bastionsupply harden` emits:

```yaml
default: deny
allow:
  - get_weather
  - search_docs
deny:
  - run_command
# behavior knobs (defaults shown)
scan_tools: true            # scan tools/list
on_poisoned_tool: block     # drop poisoned tools from the listing
scan_results: true          # scan tool-call results
on_injected_result: block   # block results carrying injection
scrub_args: true            # scan tool-call arguments for secrets/PII
on_pii_arg: redact          # redact | block | warn
scrub_results: false        # scan tool-call RESULTS for secrets/PII (opt-in)
on_pii_result: redact       # redact | block | warn
result_inspector: static    # static | agentbastion  (deeper inspection)
inspector_fail: closed      # closed | open  (behavior if the inspector errors)
inspector_judge: false      # agentbastion: also use the Anthropic LLM judge
inspector_semantic: false   # agentbastion: also use the semantic detector

# per-tool overrides — any of the knobs above, scoped to one tool
tools:
  send_email:
    scrub_args: false       # the recipient email is the point; don't redact it
  fetch:
    on_injected_result: warn
```

So the pipeline is: **scan the server with bastionsupply → `harden` a policy →
run it live behind bastiongate.**

### `policy_version: 2` (bastiongate ≥ 0.8)

The same file format agentbastion reads: a shared core (`default`, `allow`, `deny`,
`rate_limits`, `detectors`) plus one block per tool. Gate's knobs move under `gate:`:

```yaml
policy_version: 2
default: deny
allow: [get_weather, search_docs]
detectors:
  bastion.exfil_action: off        # agentbastion kill switch, applied in deep-inspect
  bastion.dan_jailbreak: shadow    # runs, named in the gate trace, never blocks
gate:
  result_inspector: agentbastion   # required for bastion.* lines
  on_injected_result: block
  tools:
    fetch: {on_injected_result: warn}
```

- **Gate's own checks have no detector IDs: the knobs are the modes.**
  `off` = `scan_tools` / `scan_results` / `scrub_args` / `scrub_results: false`;
  `shadow` = `on_*: warn` (log only, let it through); `enforce` = `block` / `redact`.
  A `gate.*` line in `detectors:` is rejected with that mapping.
- `bastion.*` lines reach agentbastion's deep-inspect and need
  `result_inspector: agentbastion` plus `agentbastion ≥ 0.12` (the
  `bastiongateway[agentbastion…]` extras require it).
- Strict: unknown keys, typos (`scan_result`), bad actions (`wran`), a v1-style
  top-level knob in a v2 file, unknown detector IDs, or `bastion.*` lines without
  the agentbastion inspector **stop the gate at startup**, never silently.
- `default:` is required only alongside `allow` / `deny` / `rate_limits`; without
  them every tool is allowed. `rate_limits` is accepted and ignored (gate has no
  rate limiter). v1 files (no `policy_version`) load exactly as before.

### Flow guard

_bastiongate ≥ 0.9._

Every call can pass and the session can still leak. The GitHub MCP toxic flow:
the agent reads a **public issue** that carries an injection, reads a file from a
**private repo**, then opens a **pull request into the public repo** with the
private content. The flow guard tracks that sequence per session and catches the
egress call:

```bash
python -m bastiongate.demo
# bastiongate: WARN tainted egress: create_pull_request (untrusted from get_issue, private from get_file_contents) - set labels or on_tainted_egress: block
# ... -32005: bastiongate blocked tool call 'create_pull_request': ...
```

Each tool gets labels: `untrusted` (its result is attacker-reachable content),
`private` (its result is private data), `egress` (calling it sends data out). An
`egress` call after the session read both `untrusted` and `private` content is a
**tainted egress**.

- **Status: shadow.** Default `on_tainted_egress: warn` forwards the call, writes
  a `tainted_egress` trace event and prints one stderr line. `block` returns
  JSON-RPC error `-32005` naming the tools involved (never the content). The
  default moves to `block` only after the replay suite passes and a dogfood run
  over ≥ 20 real sessions shows 0 false blocks on benign flows.
- **Where labels come from** (first match wins): per-tool `labels` in the policy
  → built-in packs for common servers (exact tool names) → auto (bastionsupply
  capability categories; auto only ever adds `egress`). See what each tool gets:

  ```bash
  bastiongate labels                              # the built-in packs
  bastiongate labels --policy policy.yaml tools.json  # a tools/list dump
  ```

  | Pack | untrusted | private | egress |
  |---|---|---|---|
  | github | issue_read, list_issues, search_issues, pull_request_read, list_pull_requests, search_pull_requests, get_job_logs (+ legacy get_issue, get_issue_comments, get_pull_request, get_pull_request_comments) | get_file_contents, search_code, get_commit | issue_write, add_issue_comment, update_issue_comment, create_pull_request, update_pull_request, pull_request_review_write, add_comment_to_pending_review, add_reply_to_pull_request_comment, create_or_update_file, push_files, create_repository, fork_repository (+ legacy create_issue, update_issue) |
  | filesystem | | read_file, read_text_file, read_multiple_files | |
  | fetch | fetch | | fetch |
  | slack | slack_get_channel_history, slack_get_thread_replies | | slack_post_message, slack_reply_to_thread |
  | gmail | read_email, search_emails | read_email, search_emails | send_email |

- **GitHub same-repo rule.** A private read from the same `owner/repo` the egress
  call targets does not count, so the everyday "fix issue #N" flow (issue, file
  and PR in one repo) stays silent.
- Taint is set only by what the agent actually reads: a result the gate blocked
  (`-32002`) sets nothing, and secrets `scrub_results` redacted do not count as
  private. `private` also comes from credential-shaped secrets in a forwarded
  result (keys, tokens, JWTs), never from emails or card numbers.

```yaml
# v1 top-level (or under `gate:` in policy_version 2)
scan_flows: true            # false = off
on_tainted_egress: warn     # warn | block
label_packs: true           # false = explicit labels only
tools:
  internal_search: {labels: [private]}
  create_pull_request: {on_tainted_egress: block}   # per-tool action
```

#### Across servers (`taint_group`)

An MCP client runs one gate per server, so by default each gate sees only its own
server's taint and the common trifecta (read a page through `fetch`, a secret through
`filesystem`, send it out through `fetch`) passes. Give the gates the same `taint_group`
and each one also sees the others' taint:

```yaml
taint_group: auto     # the MCP client that spawned this gate; or a name, e.g. my-agent
```

- Rows live in one per-user SQLite file (`%LOCALAPPDATA%\bastiongate\taint.sqlite`,
  `$XDG_STATE_HOME/bastiongate/taint.sqlite`; override with `BASTIONGATE_STATE_DIR`),
  user-only on POSIX. Each row says `server:tool`, so warnings read
  `private from filesystem:read_file`; the trace event has `cross_server: true`.
- `auto` groups the gates one client spawned: on POSIX by process group, on Windows by the
  nearest ancestor process that is not a launcher (`py`, `uv`, `uvx`, `cmd`, a console-script
  shim, or the venv `python.exe` redirector right above the gate). The resolved group is in
  the trace (`taint_group` event). `auto` can merge two clients started from one shell job
  (POSIX) or miss a client that detaches its servers; a name set on every server entry is
  the reliable path (or env `BASTIONGATE_TAINT_GROUP`).
- Each gate keeps one row per tainting source (`server:tool`, at most 64 per gate), so one
  gate can never flood out the others' taint; a source read from several repos is never
  exempt.
- A live gate re-stamps its rows every minute while its own taint is live; rows not
  re-stamped for 3 minutes (the gate died, or its taint expired after 30 minutes idle) are
  ignored, so a crashed client's taint does not block the next session for long.
  `initialize` clears only this gate's own rows.
- A store problem never breaks the proxy: the check uses this gate's own taint. A lock held
  by another gate is retried on the next call (`taint_store_busy`); a corrupt or unwritable
  file prints one WARN, counts `taint_store_error` and, after 3 in a row, sharing is off for
  this gate.
- Off by default; stdio only (`run-http` refuses a `taint_group`: an HTTP gate serves
  many clients and must not pool their taint).

**Limits.** Taint lives per session per upstream server, in memory:
- a chain that crosses two MCP servers is detected only when their gates share a
  `taint_group`; a named group survives a client restart until its rows expire (30
  minutes idle), so a fresh session can inherit stale taint (warnings, not leaks);
- any local process running as the same user can write or clear rows in the store
  (it could equally read the secrets directly);
- a hostile MCP server in the group can make its gate write rows (by returning
  secret-shaped text it marks itself private; by returning an injection, untrusted), so
  it can cause warnings or blocks on the other servers' egress, never hide taint;
- stdio is one session for the process; over HTTP the key is `Mcp-Session-Id`, so
  a client that rotates it starts clean, and one that floods new ids can evict
  other sessions' taint (the `taint_evicted` metric counts it);
- an HTTP upstream that issues no session ids gets no flow guard (one warning);
- taint clears after 30 minutes with no calls, or on `initialize` (any client
  holding the session id can send one);
- auto labels come from the server's own tool descriptions, so a malicious server
  can word them to avoid `egress`: they are best-effort, packs and explicit
  `labels` are the reliable path;
- a tool with no label is never treated as egress, and auto labels need a
  `tools/list` first (packs and policy labels apply immediately);
- a private read counts only from its labelled tool or a credential-shaped secret
  in the forwarded result (text, resource and `resources/read` content); an injection
  inside a private read counts as untrusted only if the result inspector flags it;
- the very first egress call is checked before its own result taints the session,
  so exfiltration needs untrusted and private reads to have happened earlier;
- a tool call whose response takes longer than 5 minutes loses correlation: its
  result is still scanned (as `(unmatched)`) but not labelled.

Older gates silently ignore these keys: `bastionsupply doctor --policy policy.yaml`
warns when bastiongateway < 0.9 would read them.

### Encoded injection in results (`on_encoded_result`)

A payload hidden in base64, hex, binary, base32, ascii85/base85, Morse or escapes reads as
noise to a text filter but plainly to the model. The gate decodes each tool result
(bastioncorpus `variants`) and runs bastionsupply's `encoded-injection` check on the decoded
views.

```yaml
on_encoded_result: warn      # warn (default, shadow) | block (-32006)
decode_transforms: false     # true = also rot13 / leet / reversed / spaced views (results <= 64 KB)
tools:
  fetch: {on_encoded_result: block}
```

- `warn` forwards the result, logs `encoded_injection`, prints a WARN line, and counts the
  result as untrusted for the flow guard.
- `block` replaces it with error -32006.
- Encoded injections in `tools/list` definitions are warned about, never dropped.
- A tool definition over 1,000,000 characters, or every tool from the one that takes a
  `tools/list` page past 5,000,000 characters, is not scanned at all: it is handled like a
  poisoned tool (event `tools_list_oversize`). Tool scans read `description`, `title`,
  `annotations.title`, `outputSchema` and `inputSchema`.

**Limits:**
- Results over 1,000,000 characters are not decoded. They are refused under `block`, and only
  logged (`encoded_scan_skipped`) under `warn`.
- rot13, leetspeak and reversed text are decoded only with `decode_transforms: true` (off by
  default), and only on results up to 64 KB; a bigger result gets the run-based views only and
  the trace event `encoded_transforms_skipped`. Spaced-out letters are mostly missed (8% on
  the bench).
- Made-up ciphers can't be decoded by enumeration. Tool allow/deny lists and the flow guard
  are the controls encoding cannot bypass.

### Resource content (`scan_resources`)

Since 0.10 every result check reads all the text the model can see, not only `text` blocks:
- embedded `resource` blocks: `uri`, `text`, and `blob` base64-decoded (standard or url-safe,
  any MIME type except media: a text type decodes leniently, anything else counts when it is
  valid UTF-8; images other than SVG, audio, video, fonts, PDF and zip are never decoded);
- `resource_link` blocks (`uri`, `name`, `title`, `description`);
- `resources/read` responses (`contents[]`), checked under the pseudo tool name
  `resources/read`;
- an upstream JSON-RPC error on a `tools/call` or `resources/read` (`message` and `data`):
  clients show tool errors to the model;
- a response with no pending request (late past 5 minutes, duplicate id, unknown id): it is
  scanned under the pseudo tool name `(unmatched)` instead of passing through (trace event
  `response_unmatched`); an uncorrelated `tools/list` result is filtered like any other.

The `initialize` result's `instructions` and `serverInfo` (clients often put them in the
system prompt) are scanned like a tool definition: under `on_poisoned_tool: block` poisoned
`instructions` are removed and a poisoned `serverInfo` is replaced by `{"name": "upstream"}`
(event `instructions_poisoned`). A response the gate cannot inspect at all is replaced by
error -32002 (event `response_uninspectable`), never forwarded and never a crash. With
`scrub_results`, secrets in an upstream error message are redacted too.

The plain injection scan (-32002), the encoded scan (-32006), the PII scrub and the flow-guard
taint all see this text. Clean resources are forwarded unchanged.

```yaml
scan_resources: true           # default; false = the 0.9 behaviour (text blocks only)
tools:
  resources/read: {on_injected_result: warn}
```

`scan_resources: false` drops resource text from `tools/call` scans and lets `resources/read`
responses through entirely (no scan, scrub or taint), as in 0.9.

**Limits:**
- The PII scrub redacts `resource.text` but never rewrites a blob or a `resource_link`.
- Media blobs (images, audio, PDF...) are not inspected: the model receives them as media.

### Prompts and listings (`scan_prompts`)

Since 0.11 the gate also checks the other server text a client can hand the model:
- **`prompts/get`**: a prompt template is instructions by design ("always review...", "you
  must..."), so the full injection signatures would flag ordinary templates (98 of 1,015 real
  skill and agent files did). Only high-precision checks run: hidden or control unicode
  (allowed: an emoji joiner, a leading byte-order mark, ZWJ/ZWNJ between letters of scripts
  such as Devanagari or Persian), variation-selector steganography, a known bastioncorpus
  payload (matched after folding case, look-alike letters, markdown emphasis and trailing
  punctuation), or one hidden in an encoding. A hit is handled by `on_injected_result`
  (block: -32002, warn: forwarded and the session tainted), under the pseudo tool name
  `prompts/get`. A prompt over 1,000,000 characters is refused under block. A prompt result
  that also carries tool-result content (`content`, `contents`, `structuredContent`) or an
  error gets the full result checks instead.
- **`resources/list`, `resources/templates/list`, `prompts/list`**: each entry's name, title,
  description, uri and prompt-argument descriptions get the same checks as a tool definition.
  A poisoned, oversize or malformed entry is dropped under `on_poisoned_tool: block`
  (event `listing_poisoned`).

```yaml
scan_prompts: true              # default; false = neither is checked (0.10 behaviour)
tools:
  prompts/get: {on_injected_result: warn}
```

**Limits:** a prompt template carrying a new, never-seen injection phrase in plain text is not
flagged, and a known phrase with words inserted or reordered is missed: that is the price of
no false positives on real templates (0 of 1,015 skill and agent files flagged as prompts; the
one hit was stray byte-order marks and a zero-width space inside a CHANGELOG). With
`scan_resources: false`, resources embedded in prompts are not read. Phrase matching is
evaded by words joined with `_` or `-`, inserted commas or HTML tags, combining marks and
leetspeak. A `prompts/get` error, or a listing/prompt result that also carries `content`,
`structuredContent` or prompt `messages` it should not have, gets the full result checks,
so an error message with imperative wording ("Always call prompts/list first") can be
blocked like a tool error.

### Argument PII/secret scrub

On every `tools/call` the gate scans the arguments the agent is about to send
and, by default, **redacts** secrets/PII (`[REDACTED:<kind>]`) before they reach
the tool — API keys, AWS/GitHub/Slack tokens, private keys, JWTs, emails, SSNs,
and Luhn-valid card numbers. `on_pii_arg: block` refuses the call instead;
`warn` only logs. Only the *kind* is ever logged, never the value.

### HTTP transport

For MCP Streamable-HTTP servers, run the gate as an HTTP proxy instead:

```bash
bastiongate run-http --upstream http://127.0.0.1:8000/mcp --port 9000 --policy policy.yaml
```

Point your client at `http://127.0.0.1:9000/mcp`. JSON and SSE responses are
both gated. Binds `127.0.0.1` by default. Add `--auth-key KEY` (or env
`BASTIONGATE_PROXY_KEY`) to require an `X-Bastiongate-Key` header on every
request; the key is compared in constant time and never forwarded upstream.

`GET /__bastiongate/metrics` returns a JSON counter of what the gate has caught
(blocks by type, tools dropped, pending/session counts). It's auth-gated when a
key is set. In stdio mode the same counters are written to the trace at exit.

### Deeper result inspection (agentbastion)

`result_inspector: agentbastion` swaps the static signature scan for
[agentbastion](https://github.com/Rinkia/agentbastion)'s inbound Firewall,
composed of up to three tiers: heuristics (always), the semantic detector
(`inspector_semantic: true` + `BASTIONGATE_EMBED_URL`), and the Anthropic LLM
judge (`inspector_judge: true` + `ANTHROPIC_API_KEY`).

```bash
pip install "bastiongateway[agentbastion]"           # heuristic
pip install "bastiongateway[agentbastion-local]"     # + semantic (local model, no egress)
pip install "bastiongateway[agentbastion-semantic]"  # + semantic (remote embed endpoint)
pip install "bastiongateway[agentbastion-judge]"     # + LLM judge
```

The semantic detector needs an embedder, chosen by env:

- `BASTIONGATE_EMBED_MODEL` — a local sentence-transformers model (e.g.
  `all-MiniLM-L6-v2`). Result text never leaves the process. **Preferred.**
- `BASTIONGATE_EMBED_URL` — a self-hosted embeddings endpoint (result text is
  POSTed to it).

The model is loaded and its templates embedded **at gate startup** (not on the
first result), bounded by `BASTIONGATE_EMBED_INIT_TIMEOUT` (default 120s); set
`BASTIONGATE_EMBED_WARM=0` to defer. For air-gapped hosts, pre-cache the model
and set `HF_HUB_OFFLINE=1` — the first uncached load fetches from HuggingFace.

## Try it

```bash
bastiongate run --log gate.jsonl -- python examples/echo_server.py
```

The example server offers a poisoned tool and an injected result; the gate drops
the first and blocks the second. Watch `gate.jsonl`.

## Library

```python
from bastiongate import Gate, GatePolicy

gate = Gate(GatePolicy(deny={"run_command"}))
forward, reply = gate.handle_client_msg(msg)   # agent -> server
out = gate.handle_server_msg(response)          # server -> agent
```

`Gate` is a pure message transform — easy to embed or test.

## Security notes & limitations

- **Argument redaction can alter legitimate calls.** `on_pii_arg: redact`
  rewrites anything that looks like PII — including a recipient email a
  `send_email` tool actually needs. Scope it with a per-tool `scrub_args: false`
  or `on_pii_arg: warn` (see `tools:` above). Scrubbing is best-effort DLP:
  base64-encoded or field-split secrets can slip through.
- Result scrub covers both `text` content blocks and `structuredContent`, and
  the injection scan reads `structuredContent` too (not only text blocks).
- The HTTP listener throttles an IP after repeated auth failures (`429`), and
  correlation state is bounded per session (LRU eviction) with an idle TTL.
- **The HTTP proxy adds no auth of its own.** It binds `127.0.0.1` by default
  and passes the client's `Authorization` header through to the upstream. Do
  not bind a public interface without an auth layer in front.
- The HTTP proxy does not follow upstream redirects and only speaks
  `http`/`https` — a malicious upstream cannot bounce it to `file://` or an
  internal address.
- **JSON-RPC batch arrays** on the request side: a batch containing `tools/call`
  is rejected (`400`), since it would bypass tool policy and the flow guard; other
  batches (notifications) pass through, and responses are still scanned. Single
  messages — the normal case — are fully gated. Chunked request bodies (no `Content-Length`) are not supported.
- `inspector_fail: closed` (default) blocks a result if the inspector errors or
  times out. The LLM judge runs on every result (cost + latency); it has a
  `BASTIONGATE_JUDGE_TIMEOUT` (default 10s).

MIT.
