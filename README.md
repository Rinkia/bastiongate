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
result_inspector: static    # static | agentbastion  (deeper inspection)
inspector_fail: closed      # closed | open  (behavior if the inspector errors)
inspector_judge: false      # agentbastion: also use the Anthropic LLM judge
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
both gated. Binds `127.0.0.1` by default.

### Deeper result inspection (agentbastion)

`result_inspector: agentbastion` swaps the static signature scan for
[agentbastion](https://github.com/Rinkia/agentbastion)'s inbound Firewall
(heuristics by default; the Anthropic LLM judge with `inspector_judge: true`
and `ANTHROPIC_API_KEY` set). Requires the extra:

```bash
pip install "bastiongateway[agentbastion]"          # heuristic
pip install "bastiongateway[agentbastion-judge]"    # + LLM judge
```

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
  `send_email` tool actually needs. For tools that legitimately take such
  values, set `on_pii_arg: warn` or `scrub_args: false`. Scrubbing is
  best-effort DLP: base64-encoded or field-split secrets can slip through.
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
