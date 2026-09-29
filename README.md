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

**Limits.** Taint lives per session per upstream server, in memory:
- a chain that crosses two MCP servers (two gate processes) is **not** detected
  (TODOS.md E4);
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
  in a forwarded **text** block (not embedded `resource` blocks); an injection
  inside a private read counts as untrusted only if the result inspector flags it;
- the very first egress call is checked before its own result taints the session,
  so exfiltration needs untrusted and private reads to have happened earlier;
- a tool call whose response takes longer than 5 minutes loses correlation, and
  its result is not labelled.

Older gates silently ignore these keys: `bastionsupply doctor --policy policy.yaml`
warns when bastiongateway < 0.9 would read them.

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
