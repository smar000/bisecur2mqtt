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
3. **Invalid port → error code 10 or LOGOUT** — querying a port outside the active range returns error code 10 (labelled `PORT_ERROR` in `legacy/pysecur3/MCP.py`'s reverse-engineered enum — that name is *not* Hörmann-documented, just a guess by that library's author) or an unsolicited LOGOUT. Either terminates or disrupts the session.
   **⚠️ UNCONFIRMED, TBC (2026-08-20):** error code 10 has also been directly observed on `SET_STATE`/`GET_TRANSITION` calls for perfectly valid, active ports, on commands that went on to succeed anyway (watched the door complete a full open/close traverse while every call in the sequence — including the initiating `SET_STATE` — raised this exact error, confirmed via raw packet capture with a correctly-matching session token, so it wasn't a parsing bug). So code 10 does **not** reliably mean "invalid port" or "command failed" in all contexts — it may be contextual/multi-purpose, or the reverse-engineered label may just be wrong for this case. `_do_door_action()` in `bisecur2mqtt.py` treats code 10 as non-fatal for door actions as a result (see `_AMBIGUOUS_GW_ERROR_CODE`), but this is a guess/workaround, not a proven root cause — revisit if better evidence turns up. It also does *not* explain the "door moves for a few seconds then stops" symptom by itself; that still looks best explained by a controller (e.g. openHAB) publishing the same directional command twice in quick succession, which the operator likely reads as a second press (stop/reverse) — see the duplicate-command fix below.
4. **One session at a time** — running the CLI while the service is up triggers a reconnect in the service.
5. **⚠️ FIRMWARE BUG: Intermittent unresponsiveness** — The gateway (firmware EE001425-08) has a known issue where it becomes completely unresponsive, rejecting all commands/queries with PORT_ERROR even though ports exist. Root causes identified:
   - **Rapid command sequences**: Sending directional commands (up/down) within ~7 seconds triggers rate limiting or buffer overflow
   - **Long position polling**: Aggressive polling (every 1s) while gateway is rate-limited can cause session corruption
   - Recovery: Physical reboot of gateway device required. Service monitors this and alerts via MQTT (`gateway_health` attribute). The gateway sits on a zigbee smart socket, so this can be done remotely without a physical visit: publish `ON`/`OFF` to `zigbee2mqtt/garage_bisecure_gateway/set` (`ON` = socket powered/gateway on, `OFF` = socket powered off/gateway off). Cycle OFF then ON and allow boot time before retesting.
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

- **Directional commands** (up, down, impulse, partial, light): Minimum 2-second spacing enforced between *different* actions
- **Duplicate of the same action within 2s is dropped, not delayed** — see below
- **STOP commands**: Bypass rate limiting (always allowed immediately for safety)
- Logged as: `Rate limiting: <action> delayed X.XXs (last command: <action>, X.Xs ago)`

Example sequences:
- `up` → wait 2s → `down` ✅ delayed to 2s minimum spacing
- `up` → wait 1s → `stop` ✅ (STOP allowed immediately)
- `down` → `down` (same action, within 2s) → **second one dropped**, logged as `Ignoring duplicate 'down' (...)`

This prevents the scenario that caused Aug 14 lockup:
- ❌ Old behavior: `up` (09:29:11) + `down` (09:29:18) → gateway unresponsive after 46 min
- ✅ New behavior: `up` → `down` delayed to meet 2-second minimum

**Duplicate-command bug (found & fixed 2026-08-20):** the first version of this rate limiter
delayed a *repeated* same-direction command (e.g. two `down` messages published back-to-back by
a flaky controller) rather than dropping it — so instead of both hitting the gateway near-
simultaneously (harmless), the second one landed ~2-3s later while the door was genuinely mid-
travel. BiSecur-wired operators read a second press while already moving as stop/reverse, so the
door would run for a couple of seconds and stop, requiring repeated impulses to complete a
traverse. Fix: a repeat of the *same* action within the 2s window is now dropped outright instead
of delayed-and-resent. A genuinely different action (e.g. `up` then `down`) is still delayed as
before, since that's the real gateway buffer-overflow protection this was built for.

## Gateway Health Monitoring

The service now detects when the gateway becomes unresponsive:

- Tracks consecutive position query failures
- After 5 consecutive failures: logs error and publishes `bisecur2mqtt/attributes/gateway_health = "unresponsive"`
- When queries succeed again: logs recovery and sets `gateway_health = "ok"`
- This helps diagnose whether the gateway needs rebooting

## Known issues (found 2026-08-20, not yet fixed)

1. **`_track_door_position()` has no cap/timeout on repeated `BisecurError`.** If the
   gateway keeps erroring on every position query, the loop just polls forever at
   1 req/s with no backoff or give-up condition. Observed a 9-minute unbroken instance
   of this in production logs.
2. **Neither that loop's `ConnectionError` path nor `_periodic_poll_worker()` call
   `_trigger_reconnect()`** on disconnect — both just log/skip. The service currently
   only self-heals when the *next* incoming MQTT command arrives and `do_command()`
   notices `gateway.is_connected` is False. There's a real window (observed ~2.5
   minutes) where the service is fully disconnected and silent — not polling, not
   alerting, not reconnecting on its own.

## Running the CLI

```bash
python3 bisecur_cli.py status          # gateway info
python3 bisecur_cli.py impulse         # trigger door
python3 bisecur_cli.py -v position     # verbose: see raw protocol
python3 bisecur_cli.py cleanup         # drain stale sessions + logout
```
