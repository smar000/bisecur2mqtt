# bisecur2mqtt — Claude Code context

## What this project is

A local MQTT bridge for a Hormann BiSecur garage door gateway. The gateway speaks a proprietary binary protocol (MCP) over TCP port 4000. This project translates between that and MQTT, and also provides a CLI tool for direct gateway control.

**Live gateway:** 172.16.3.20, firmware EE001425-08, MAC D8:80:39:BC:E1:40 (check bisecur2mqtt.conf for current values).  
**Active ports:** 1–5 (names blank). impulse=1, light=2, partial=3, up=4, down=5.  
**Group:** "Garage Door" contains ports 1–4 (port 5/down is outside the group).  
**One user:** admin (isAdmin=true).

## Key files

| File | What it does |
|------|-------------|
| `bisecur_client.py` | Self-contained MCP protocol client. The only file that opens a socket to the gateway. Thread-safe via internal lock. |
| `bisecur2mqtt.py` | MQTT bridge service. Imports `bisecur_client`. Handles reconnect, position tracking, HA autodiscovery. |
| `bisecur_cli.py` | CLI tool. Imports `bisecur_client`. Each invocation does connect→login→action→disconnect. |
| `bisecur2mqtt.conf` | Live config (gitignored). `bisecur2mqtt.conf.sample` is the tracked template. |
| `docs/REFERENCE.md` | Protocol internals, quirks, threading model, how to add commands. Read this before touching the protocol. |
| `misc/bisecur2mqtt.service` | systemd unit file. Copy to `/etc/systemd/system/` to run as a service. |
| `misc/test_gateway.py` | Integration smoke-test. Prints firmware version, port scan, users, groups. Uses DEBUG logging. |
| `legacy/` | Original pysecur3 library and tools. Not used. Kept for protocol reference — `legacy/pysecur3/MCP.py` has the full command enum. |

## Protocol in one paragraph

TCP socket, port 4000. Everything on the wire is upper-case hex-encoded ASCII (each byte → 2 ASCII chars). Outer packet: `SRC_MAC(6) + DST_MAC(6) + MCP_PAYLOAD + PKT_CRC(1)`. MCP payload: `LENGTH(2) + TAG(1) + TOKEN(4) + CMD_ID(1) + DATA + MCP_CRC(1)`. PKT_CRC = sum of ASCII ordinals of the hex string mod 256. MCP_CRC = rolling sum starting from LENGTH as uint16. TAG and TOKEN come from the login response and go in every subsequent packet header. Full details in `docs/REFERENCE.md` and the docstring at the top of `bisecur_client.py`.

## Critical gateway quirks

1. **Pre-login LOGOUT flood** — on reconnect, the gateway sends N stale LOGOUTs before the login response. `login()` drains up to 20 of them. Do not change this.
2. **All active ports return overall door position** — `CMD_GET_TRANSITION` works on any configured port; they all return the same position. Service defaults to `impulse_port`.
3. **Invalid port → PORT_ERROR or LOGOUT** — querying a port outside the active range returns error code 10 (PORT_ERROR) or an unsolicited LOGOUT. Either terminates or disrupts the session.
4. **One session at a time** — running the CLI while the service is up triggers a reconnect in the service.
5. **⚠️ FIRMWARE BUG: Intermittent unresponsiveness** — The gateway (firmware EE001425-08) has a known issue where it becomes completely unresponsive, rejecting all commands/queries with PORT_ERROR even though ports exist. Root causes identified:
   - **Rapid command sequences**: Sending directional commands (up/down) within ~7 seconds triggers rate limiting or buffer overflow
   - **Long position polling**: Aggressive polling (every 1s) while gateway is rate-limited can cause session corruption
   - Recovery: Physical reboot of gateway device required. Service monitors this and alerts via MQTT (`gateway_health` attribute).
   - Mitigation: Rate limiting enforced — directional commands spaced minimum 2 seconds apart. STOP commands bypass rate limit (emergency operation).

## Port discovery

`GET_GROUPS` (JCMP) returns the "Garage Door" group with ports 1–4.  
`GET_VALUES` (JCMP) returns all 64 slots as zeros — useless.  
**Most reliable:** scan `GET_PORT_NAME` (cmd 52) on ports 0–31; returns data for valid ports, gateway error for invalid ones.

## Config loading

Both `bisecur2mqtt.py` and `bisecur_cli.py` parse the config with `ast.literal_eval` — safe, no `exec`. Config path from env var `BISECUR2MQTT_CONFIG`, defaulting to `bisecur2mqtt.conf`.

## Threading

`BisecurGateway` is thread-safe. Public methods acquire `self._lock`. `connect()` and `login()` do NOT acquire the lock — only call them from single-threaded context or from `reconnect()`. The service runs: main thread (MQTT loop) + MQTT callback thread + position tracking thread + reconnect thread.

## Extending the client

Add a `CMD_*` constant, add a method that calls `_send_recv(CMD_*, payload)` inside `with self._lock:`, check `legacy/pysecur3/MCP.py` for payload encoding. Then wire it into `bisecur_cli.py` if needed.

## Service management

```bash
systemctl status bisecur2mqtt
systemctl restart bisecur2mqtt
journalctl -u bisecur2mqtt -f
```

## Rate Limiting

The service implements **command rate limiting** to prevent gateway firmware lockups:

- **Directional commands** (up, down, impulse, partial, light): Minimum 2-second spacing enforced
- **STOP commands**: Bypass rate limiting (always allowed immediately for safety)
- Logged as: `Rate limiting: <action> delayed X.XXs (last command: <action>, X.Xs ago)`

Example safe sequences:
- `up` → wait 2s → `down` ✅
- `up` → wait 1s → `stop` ✅ (STOP allowed immediately)
- `down` → `down` (same within 2s) → delayed to 2s ✅

This prevents the scenario that caused Aug 14 lockup:
- ❌ Old behavior: `up` (09:29:11) + `down` (09:29:18) → gateway unresponsive after 46 min
- ✅ New behavior: `up` → `down` delayed to meet 2-second minimum

## Gateway Health Monitoring

The service now detects when the gateway becomes unresponsive:

- Tracks consecutive position query failures
- After 5 consecutive failures: logs error and publishes `bisecur2mqtt/attributes/gateway_health = "unresponsive"`
- When queries succeed again: logs recovery and sets `gateway_health = "ok"`
- This helps diagnose whether the gateway needs rebooting

## Running the CLI

```bash
python3 bisecur_cli.py status          # gateway info
python3 bisecur_cli.py impulse         # trigger door
python3 bisecur_cli.py -v position     # verbose: see raw protocol
python3 bisecur_cli.py cleanup         # drain stale sessions + logout
```
