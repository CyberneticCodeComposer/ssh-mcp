# Upstream defect: MCP client rewrites tool input schemas and marks defaulted parameters required

**Status:** open upstream, not filed yet. Worked around server-side in ssh-mcp 0.16.0.
**Observed:** 2026-09-15
**Severity:** high — renders individual tools completely uncallable, silently.

## Summary

An MCP client is transforming the JSON Schema that servers advertise for their
tool inputs, and then enforcing a *stricter* contract than the server declared.
Two independent faults compound:

1. **Optionality is lost.** Every parameter carrying a `default` is treated as
   required. The server's own `required` list is not honored.
2. **Type information is lost.** A nullable union
   (`anyOf: [{type: X}, {type: "null"}]`) is collapsed to a property with **no
   `type` at all**, and `integer` is flattened to `number`.

Fault 1 alone is usually survivable: the caller can just send the default value.
It becomes **fatal** whenever a parameter is optional *because its valid domain
is empty in the current call* — the caller is forced to send a value, and every
value it can send is semantically wrong, so the server correctly rejects all of
them. There is then no call that satisfies both sides.

This is not a bug in any one server. It reproduces across three unrelated MCP
servers in this environment (see [Scope](#scope)).

## Reproduction

Server: `ssh-mcp` 0.15.0 (FastMCP 3.3.1). Tool: `ssh_run_command`. The `vdom`
parameter is FortiOS-only; on any other platform a VDOM name is rejected
*before connecting*, because the parameter names a device context that the
platform does not have.

### Step 1 — omit the optional parameter

```
ssh_run_command(host="192.0.2.1", platform="cisco-iosxe", command="show clock")
```

```
MCP error -32602: Input validation error: Invalid arguments for tool ssh_run_command: [
  { "code": "invalid_type", "expected": "nonoptional", "path": ["credential_profile"],
    "message": "Invalid input: expected nonoptional, received undefined" },
  { "code": "invalid_type", "expected": "nonoptional", "path": ["port"], ... },
  { "code": "invalid_type", "expected": "nonoptional", "path": ["timeout"], ... },
  { "code": "invalid_type", "expected": "nonoptional", "path": ["vdom"], ... }
]
```

All four parameters that carry a default are demanded. None is in the server's
`required` list.

### Step 2 — supply it

```
ssh_run_command(host="192.0.2.1", platform="cisco-iosxe", command="show clock",
                credential_profile="default", port=22, timeout=10, vdom="root")
```

```
ToolError: `vdom` is only supported on FortiOS platforms
('fortios','fortinet','fortigate'); platform is 'cisco-iosxe'. Omit it.
```

The client demands the key; the server rejects the key. `port=22`,
`timeout=10` and `credential_profile="default"` are satisfiable by passing the
default. `vdom` is not: every VDOM name a caller can type is a non-empty
string, and a non-empty `vdom` is exactly what the server refuses here. Before
the workaround, `ssh_run_command` and `ssh_run_commands` were **uncallable on
every non-FortiOS platform** — `cisco-iosxe`, `aruba-cx`, `arista-eos`,
`linux`, and the rest.

## Evidence: what the server advertises vs. what the client enforces

Read off the wire from the server's own `list_tools` response, via a
`fastmcp.Client` over stdio against the same server binary and launch command
the client uses:

```
SERVER-ADVERTISED required:    ['host', 'platform', 'command']
SERVER-ADVERTISED vdom schema: [{"type": "string"}, {"type": "null"}]
```

Full server-side property shapes (identical from `mcp.get_tool(...).parameters`
and from the stdio wire response):

| parameter            | server advertises                                              | client enforces                              |
| -------------------- | -------------------------------------------------------------- | -------------------------------------------- |
| `host`               | `{"type":"string"}`, in `required`                              | required — correct                            |
| `vdom`               | `{"anyOf":[{"type":"string"},{"type":"null"}],"default":null}`   | **required**; `anyOf` stripped, no `type`     |
| `timeout`            | `{"anyOf":[{"type":"number"},{"type":"null"}],"default":null}`   | **required**; `anyOf` stripped, no `type`     |
| `port`               | `{"type":"integer","default":22}`                               | **required**; `integer` → `number`            |
| `credential_profile` | `{"type":"string","default":"default"}`                         | **required**                                  |

So the server is behaving correctly and the deadlock is created entirely on the
client side. The three observed transformations:

- **`anyOf` unwrapping drops the type.** `str | None` arrives as
  `{"default": null, "description": ...}` — no `type` key at all. Confirmed
  firsthand on two other servers (below).
- **`integer` is flattened to `number`.** Loses integrality; a client could
  now send `22.5` for an SSH port.
- **`default` is read as "must be supplied".** The presence of a `default` is
  precisely the marker that a parameter *may be omitted*; it is being treated
  as the opposite, and the server's `required` array is discarded.

The error's `"expected": "nonoptional"` and `"code": "invalid_type"` shape is
Zod v4 (`z.nonoptional()`). That places the fault in the client's
JSON-Schema → Zod conversion step, downstream of the schema rewrite and
upstream of dispatch: a property with a `default`, no `type`, and no entry in
`required` is being compiled to a non-optional validator instead of an optional
one.

## Scope

Not server-specific. Confirmed firsthand on three unrelated servers, each a
separate codebase:

| server          | tool                     | parameters wrongly demanded             | escapable? |
| --------------- | ------------------------ | --------------------------------------- | ---------- |
| `ssh-mcp`       | `ssh_run_command`        | `credential_profile`, `port`, `timeout`, `vdom` | **no** (before workaround) |
| `netbox`        | `list_devices`           | `site`, `role`, `status`, `tag`, `offset` | **no** |
| `netbox`        | `lookup_platform`        | `manufacturer`, `q`, `limit`, `offset`   | **no** |
| `aruba-central` | `aruba_central_list_gateways` | `cursor`                            | yes       |

The nullable parameters on the other two servers show the identical fingerprint
— `type` gone, bare `default: null`:

```
netbox list_devices:            "site":   {"default": null, "description": "Site slug to filter by"}
aruba-central list_gateways:    "cursor": {"default": null, "description": "Next-page cursor"}
```

`netbox.list_devices` is the worst case found, and is **worse than ssh-mcp's**:
the forced placeholder is passed through to the NetBox REST API, which validates
it against a choice list and rejects it.

```
site="null", role="null", status="null", tag="null"
  -> 400 errors={'status': ['Select a valid choice. null is not one of the available choices.']}

site="", role="", status="", tag=""
  -> 400 errors={'tag': ['Select a valid choice.  is not one of the available choices.'],
                 'role': [...], 'site': [...], 'status': [...]}
```

`lookup_platform` fails the same way (`manufacturer=""` →
`400 errors={'manufacturer': ['Select a valid choice.  is not one of the available choices.']}`).
Both tools are currently uncallable by any argument combination. A server-side
normalization like the one below would fix them there too.

### Severity depends on the parameter's semantics

1. **Harmless** — the default is a passable value (`port=22`, `limit=50`).
   The caller just restates it. Noisy, not blocking.
2. **Fatal at the server's policy layer** — the parameter is optional because
   its domain is empty for this call, so every passable value is rejected.
   *ssh-mcp `vdom`.*
3. **Fatal at the backend** — the placeholder is forwarded to an upstream API
   that validates it. *netbox `list_devices`.*

Classes 2 and 3 cannot be worked around by the caller. Both fail *after* the
tool looked available and well-formed, so the failure reads as a server bug.

## What a correct client fix looks like

1. **Honor the server's `required` array verbatim.** Do not recompute
   optionality, and never infer it from the presence of a `default`. A property
   not listed in `required` is optional; a `default` reinforces that it may be
   omitted.
2. **Preserve `anyOf` / nullable unions**, or at minimum keep a `type` when
   collapsing them. Emitting a typeless property loses the information needed
   to build a correct validator.
3. **Preserve `integer` vs `number`.**
4. **Prefer omission over placeholder injection.** If a defaulted parameter
   must be materialized, the client should send JSON `null` for a nullable
   parameter or the declared `default` — never a stringified `"null"`, and
   never require the model to invent a value.

## Workaround shipped in ssh-mcp 0.16.0

Server-side only; the client is not modified. `safety.normalize_context()`
maps an empty, whitespace-only, `"null"` or `"none"` value to `None`, applied
at three points: the tool boundary (`_shared.check_vdom_supported`, which now
returns the normalized value), the connection dispatcher
(`connection.enter_context`), and the shell's context navigation
(`shell.ShellConnection.enter_context`). A client that cannot omit `vdom` sends
an empty string, which means "not supplied".

Verified against a live Cisco IOS-XE device (`show clock`), driving the patched
server over stdio:

```
vdom=''       -> failed=False vdom_echoed=None output='22:32:06.112 EDT Tue Sep 15 2026'
vdom='   '    -> failed=False vdom_echoed=None output='22:32:08.558 EDT Tue Sep 15 2026'
vdom='null'   -> failed=False vdom_echoed=None output='22:32:10.970 EDT Tue Sep 15 2026'
vdom='none'   -> failed=False vdom_echoed=None output='22:32:13.362 EDT Tue Sep 15 2026'
vdom="root"   -> rejected: `vdom` is only supported on FortiOS platforms ...
vdom omitted  -> vdom_echoed=None
```

The deny-before-connect check is unchanged for a real VDOM name, and a
placeholder can never reach the `config vdom` / `edit <name>` navigation —
`edit <unknown>` would CREATE a VDOM on a FortiGate.

### What was deliberately not done

- **Not** deleting or weakening the `vdom` platform check. It is a correct
  deny-before-connect guard; removing it would let `vdom` reach platforms with
  no device contexts.
- **Not** making `vdom` required to satisfy the client. That breaks FortiOS
  callers who legitimately omit it to run at the top-level prompt.
- **Not** patching the client from this repository.

The workaround is a mitigation, not a fix. Every other MCP server in the fleet
with a semantically-constrained optional parameter has the same latent
deadlock, and each would need its own placeholder convention. The fix belongs
in the client.

## Environment

- Client: Claude Desktop 2.110.0 (Claude Code tab), macOS 26.4.1 (build 25E253) / Darwin 25.4.0
- Server: ssh-mcp 0.15.0 → 0.16.0, FastMCP 3.3.1, MCP Python SDK, Pydantic 2.13.4, Python 3.14.3
- Transport: stdio
- Validator fingerprint: Zod v4 (`"expected": "nonoptional"`)

## Operational cost

This surfaced during a 2026-09-15 gateway ISSU maintenance window. The entire window had to be driven through a
hand-rolled expect wrapper because the MCP path was unusable on IOS-XE — the affected tools are the primary
read-only diagnostic path for the fleet.
