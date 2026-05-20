# bisecur2mqtt — Technical Reference

This document describes the internal architecture, protocol details, and known quirks of this project. It is intended for future maintainers.

---

## Project history

The project originally used the [pysecur3](https://github.com/skelsec/pysecur3) library (now in `legacy/`). That library is unmaintained and had Python 3 compatibility issues. In May 2026 the dependency was replaced with a clean, self-contained implementation in `bisecur_client.py`. All protocol knowledge was reverse-engineered from `legacy/pysecur3/MCP.py` and cross-referenced with [halacs/BiSecur](https://github.com/halacs/BiSecur).

---

## File map

| File | Role |
|------|------|
| `bisecur_client.py` | MCP protocol client — the only file that speaks to the gateway |
| `bisecur2mqtt.py` | MQTT bridge service — imports `bisecur_client`, handles MQTT I/O and reconnect logic |
| `bisecur_cli.py` | CLI tool — imports `bisecur_client`, no MQTT |
| `misc/test_gateway.py` | Integration smoke-test — connects, queries firmware, ports, users, groups |
| `misc/bisecur2mqtt.service` | systemd unit file — copy to `/etc/systemd/system/` |
| `legacy/pysecur3/MCP.py` | Best reference for the full MCP command enum and packet structures |

---

## MCP wire protocol

The gateway listens on **TCP port 4000**. All data on the wire is the **upper-case hex ASCII encoding** of the raw bytes — i.e. every byte is sent as two ASCII characters.

### Outer packet structure

```
[ SRC_MAC (6 bytes) | DST_MAC (6 bytes) | MCP_PAYLOAD (LENGTH bytes) | PKT_CRC (1 byte) ]
```

Encoded as `packet_bytes.hex().upper().encode()` before sending.

- `SRC_MAC` — the client's MAC address (any value works; use `FF:FF:FF:FF:FF:FF` or similar)
- `DST_MAC` — the gateway's MAC address (from your config)
- `PKT_CRC` — sum of the ASCII ordinal values of the hex-encoded packet string, mod 256

```python
PKT_CRC = sum(ord(c) for c in packet_hex_string.upper()) & 0xFF
```

### MCP payload structure

```
[ LENGTH (2 bytes) | TAG (1 byte) | TOKEN (4 bytes) | CMD_ID (1 byte) | DATA | MCP_CRC (1 byte) ]
```

- `LENGTH` = total byte count of the MCP payload (including the LENGTH field itself)
- `TAG` + `TOKEN` — session credentials obtained from the login response; both zero before login
- `CMD_ID` — command identifier (see table below); response packets have bit 7 set (`CMD_ID | 0x80`)
- `MCP_CRC` — running sum starting from the `LENGTH` field as a uint16, then adding each subsequent byte masked to 8 bits:

```python
cks = int.from_bytes(length_bytes, 'big')
for b in remaining_bytes:
    cks = (cks + b) & 0xFF
MCP_CRC = cks & 0xFF
```

### Packet reading

The gateway sends hex-encoded ASCII. To read one packet:
1. Buffer at least 28 ASCII chars (= 14 bytes decoded: SRC+DST MACs)
2. Decode bytes 12–13 of the raw packet to get `LENGTH`
3. Full packet size = `(13 + LENGTH) * 2` ASCII chars (13 = 6+6+1 for MACs + PKT_CRC)
4. Decode the full packet, verify both CRCs, extract the data field

---

## MCP command IDs

| Constant | ID (dec) | Direction | Description |
|----------|----------|-----------|-------------|
| `CMD_PING` | 0 | → | Keepalive ping |
| `CMD_ERROR` | 1 | ← | Gateway error response; `data[0]` is the error code |
| `CMD_JCMP` | 6 | ↔ | JSON sub-protocol (see below) |
| `CMD_GET_GW_VERSION` | 7 | → | Request firmware version string |
| `CMD_LOGIN` | 16 | → | Authenticate; payload: `[len(username)] + username + password` |
| `CMD_LOGOUT` | 17 | ↔ | End session (sent by client or gateway) |
| `CMD_GET_USER_RIGHTS` | 40 | → | Request port access list; payload: `\x00` |
| `CMD_GET_STATE` | 50 | → | Request current state byte for a port; payload: `[port_id]` |
| `CMD_SET_STATE` | 51 | → | Trigger door action; payload: `[port_id, command_value]` |
| `CMD_GET_PORT_NAME` | 52 | → | Request port name string; payload: `[port_id]` |
| `CMD_GET_TRANSITION` | 112 | → | Request door position 0–100%; payload: `[port_id]` |

Full enum (including many unused commands) is in `legacy/pysecur3/MCP.py` under `MCPCommand`.

---

## Session lifecycle

### Login

```
client  →  CMD_LOGIN  (username/password payload)
gateway →  [0..N × CMD_LOGOUT]   ← stale sessions being flushed (see quirks)
gateway →  CMD_LOGIN response     ← data: [TAG(1), TOKEN(4), ...]
```

The login response data contains the session TAG (1 byte) and TOKEN (4 bytes). These must be included in the header of every subsequent packet. Both are zero before login.

### Logout

```
client  →  CMD_LOGOUT  (empty payload, using current TAG+TOKEN)
gateway →  CMD_LOGOUT response
```

`disconnect()` always calls `logout()` first. If the send fails it still closes the socket.

### Unsolicited LOGOUT

If the gateway sends a `CMD_LOGOUT` mid-session (e.g. session timeout, another client logged in), `_send_recv()` detects it, closes the socket, and raises `ConnectionError`. `bisecur2mqtt.py` catches this and calls `reconnect()`.

---

## JCMP sub-protocol

`CMD_JCMP` (6) carries a JSON payload. The request and response are both raw JSON bytes in the `DATA` field of the MCP packet.

### Known JCMP commands

| JSON `CMD` | Description |
|-----------|-------------|
| `GET_VALUES` | All 64 port slots with state values (mostly zeros if ports unused) |
| `GET_USERS` | List of user objects: `{id, name, isAdmin, groups}` |
| `GET_GROUPS` | List of group objects (empty if no groups configured) |

Example request payload: `{"CMD":"GET_USERS"}` (no spaces; separators `(',', ':')`)

**Note:** The gateway also accepts lowercase `cmd` key, but we use uppercase `CMD` for consistency with the working `GET_GROUPS` call.

---

## Port discovery

The gateway has no single command that reliably returns "which ports are active" in all configurations:

| Command | Result on this gateway |
|---------|----------------------|
| `GET_VALUES` (JCMP) | Returns all 64 slots, all with value 0 — useless |
| `GET_GROUPS` (JCMP) | Returns configured groups with their port lists — useful if groups exist |
| `CMD_GET_USER_RIGHTS` (40) | May return empty for admin users who bypass the group system |
| `CMD_GET_PORT_NAME` (52) | Returns port name or raises gateway error; **most reliable detector** |

The working approach: scan port IDs 0–31, call `get_port_name(id)` on each. The gateway returns data (even an empty string) for valid ports and raises a gateway error for invalid ones. `bisecur_cli.py status` does this automatically.

On this gateway the `GET_GROUPS` JCMP response reveals a group named `"Garage Door"` containing ports 1–4. Port 5 (down) exists outside the group. Port names are blank (not configured in the app).

---

## Known gateway quirks (firmware EE001425-08)

### 1. Pre-login LOGOUT flood
When a session is abandoned without a clean logout (e.g. process crash, timeout), the gateway queues LOGOUT packets. On the next login it sends these stale LOGOUTs **before** the login response. `login()` drains up to 20 of these before treating the next packet as the login response.

### 2. All active ports return overall door position
`CMD_GET_TRANSITION` (112) works on any configured port — they all return the same overall door position (0–200 raw → 0–100%). The service defaults to `impulse_port` for position queries. Override with `position_port` in config if needed.

### 3. Invalid port causes LOGOUT
Querying `CMD_GET_TRANSITION` on a port outside the active range causes the gateway to return `PORT_ERROR` (error code 10) or an unsolicited LOGOUT, which terminates the session. The service raises `BisecurError` on error codes and `ConnectionError` on unsolicited LOGOUT, triggering reconnect. Do not query positions on ports beyond the known active range.

### 4. One session at a time
The gateway allows only one active authenticated session. Running `bisecur_cli.py` while `bisecur2mqtt.service` is running will cause the service to receive an unsolicited LOGOUT and trigger a reconnect.

---

## Threading model (bisecur2mqtt.py)

| Thread | Purpose |
|--------|---------|
| Main thread | MQTT loop (`loop_forever`) |
| MQTT callback thread | `on_message` → `do_command()` → `gateway.set_door_state()` |
| Position tracking thread | Polls `get_door_position()` every second while door is in motion |
| Periodic poll thread | Wakes every `position_poll_interval` minutes to refresh and publish door position; skips cycle if tracking thread is active. Restarted atomically by `_restart_periodic_poll()` when interval is changed at runtime via `set_poll_interval`. |
| Reconnect thread | Started on `ConnectionError`; calls `gateway.reconnect()` with exponential backoff |

`BisecurGateway` is thread-safe: all public operations (`get_door_position`, `set_door_state`, etc.) acquire an internal `threading.Lock`. `connect()` and `login()` do **not** acquire the lock and must only be called from single-threaded context or from within `reconnect()` which already holds the lock.

---

## Config file format

The config file uses plain Python assignment syntax (`key = value`) and is parsed safely with `ast.literal_eval` — no `exec`, no arbitrary code execution. Only simple literal assignments are read; anything else is silently skipped.

```python
bisecur_ip   = '172.16.3.20'
bisecur_mac  = 'D8:80:39:BC:E1:40'
bisecur_user = 'admin'
bisecur_pw   = 'secret'
```

The config file is selected via the `BISECUR2MQTT_CONFIG` environment variable, defaulting to `bisecur2mqtt.conf` in the working directory.

### Logging config keys

| Key | Default | Description |
|-----|---------|-------------|
| `log_dir` | `.` | Directory for log files; file is named after the script (`bisecur2mqtt.log`) |
| `log_max_size_mb` | `10` | Max log file size in MB before rotation |
| `log_backup_count` | `5` | Number of rotated files to keep (`.log.1` … `.log.N`) |
| `debug` | `False` | Enable DEBUG-level logging |
| `debug_jcmp` | `False` | Log all JCMP JSON request/response pairs at INFO level |
| `debug_packets` | `False` | Log raw hex packet data at INFO level (very verbose) |

---

## Adding a new gateway command

1. Add a `CMD_*` constant to `BisecurGateway` in `bisecur_client.py`
2. Add a public method that calls `self._send_recv(self.CMD_*, payload)` inside `with self._lock:`
3. Refer to `legacy/pysecur3/MCP.py` for the payload format of each command (the `to_bytes` methods on each `MCP*` class show the encoding)
4. Add the command to `bisecur_cli.py` if it warrants a CLI entry point
