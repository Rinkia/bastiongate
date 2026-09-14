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
- Result scrub covers both `text` content blocks and `structuredContent`.
- The HTTP listener throttles an IP after repeated auth failures (`429`), and
  correlation state is bounded per session with an idle TTL.
- **The HTTP proxy adds no auth of its own.** It binds `127.0.0.1` by default
  and passes the client's `Authorization` header through to the upstream. Do
  not bind a public interface without an auth layer in front.
- The HTTP proxy does not follow upstream redirects and only speaks
  `http`/`https` — a malicious upstream cannot bounce it to `file://` or an
  internal address.
- **JSON-RPC batch arrays** on the request side are passed through un-gated
  (responses are still scanned); single messages — the normal case — are fully
  gated. Chunked request bodies (no `Content-Length`) are not supported.
- `inspector_fail: closed` (default) blocks a result if the inspector errors or
  times out. The LLM judge runs on every result (cost + latency); it has a
  `BASTIONGATE_JUDGE_TIMEOUT` (default 10s).

MIT.
