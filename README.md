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
```

So the pipeline is: **scan the server with bastionsupply → `harden` a policy →
run it live behind bastiongate.**

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

## Notes

- **stdio transport** only for now (the common locally-installed case).
  HTTP/SSE is the next transport.
- Result scanning reuses bastionsupply's static injection signatures. Swapping
  in agentbastion's `Firewall` (LLM judge, semantic detector, PII scrub) is the
  planned deeper-inspection upgrade.

MIT.
