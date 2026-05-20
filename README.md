# bisecur2mqtt

An MQTT bridge for the Hormann BiSecur Gateway, allowing local network control of BiSecur-compatible garage doors and gates via MQTT — with Home Assistant and openHAB autodiscovery support.

## Overview

The service connects to the BiSecur gateway over TCP (port 4000) using the Hormann MCP protocol, subscribes to an MQTT topic for commands, and publishes door state, position, and light state back to MQTT. A standalone CLI tool is also provided for direct gateway control without MQTT.

**Hardware:** Hormann BiSecur Gateway (tested on firmware `EE001425-08`)

## Repository structure

```
bisecur2mqtt.py          Main MQTT bridge service
bisecur_client.py        BiSecur MCP protocol client library
bisecur_cli.py           Command-line tool for direct gateway control
bisecur2mqtt.conf.sample Config file template (copy to bisecur2mqtt.conf)
misc/
  bisecur2mqtt.service   systemd unit file
  test_gateway.py        Integration smoke-test (connect, query status)
legacy/
  pysecur3/              Original pysecur3 library (reference only)
  pysecur3_tools/        Original pysecur3 tools (reference only)
docs/
  REFERENCE.md           Protocol internals and maintenance guide
```

## Dependencies

```
pip install paho-mqtt
```

Python 3.10+ required (uses `X | Y` union type hints).

## Setup

### 1. Config file

Copy the sample and fill in your values:

```bash
cp bisecur2mqtt.conf.sample bisecur2mqtt.conf
```

**Finding port numbers:** Run `python3 bisecur_cli.py status` — it scans the gateway and lists all active ports with their IDs.

| Key | Required | Description |
|-----|----------|-------------|
| `bisecur_ip` | yes | IP or hostname of the gateway |
| `bisecur_mac` | yes | Gateway MAC address (colons optional) |
| `bisecur_user` | yes | Login username |
| `bisecur_pw` | yes | Login password |
| `src_mac` | yes | Spoofed source MAC (any value, e.g. `FF:FF:FF:FF:FF:FF`) |
| `impulse_port` | yes | Gateway port number for impulse command; also used for position queries |
| `up_port` | no | Port for open/up command |
| `down_port` | no | Port for close/down command |
| `partial_port` | no | Port for partial-open command |
| `light_port` | no | Port for light toggle |
| `door_name` | no | MQTT subtopic name for this door (default: `default_door`; auto-detected from gateway group name if configured) |
| `position_port` | no | Port for position queries (default: `impulse_port`) |
| `position_poll_interval` | no | Minutes between automatic position refreshes (default: `15`; set `0` to disable) |
| `mqtt_broker` | yes | MQTT broker IP or hostname |
| `mqtt_port` | no | MQTT broker port (default: `1883`) |
| `mqtt_client_id` | no | MQTT client ID (default: `bisecur2mqtt-<pid>`) |
| `mqtt_topic_base` | no | Root MQTT topic (default: `bisecur2mqtt`) |
| `mqtt_topic_HA_discovery` | no | Home Assistant discovery prefix (default: `homeassistant`) |
| `bisecur_timeout` | no | Gateway socket timeout in seconds (default: `10`) |
| `log_dir` | no | Directory for log files (default: `.`); file named `bisecur2mqtt.log` |
| `log_max_size_mb` | no | Log file size in MB before rotation (default: `10`) |
| `log_backup_count` | no | Number of rotated log files to keep (default: `5`) |
| `debug` | no | Set `True` for verbose protocol logging (default: `False`) |
| `debug_jcmp` | no | Set `True` to log all JCMP JSON request/response pairs (default: `False`) |
| `debug_packets` | no | Set `True` to log raw hex packet data — very verbose (default: `False`) |

### 2. Run as a service

```bash
sudo cp misc/bisecur2mqtt.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable bisecur2mqtt
sudo systemctl start bisecur2mqtt
```

The service file assumes the repo is at `/opt/bisecur`. Adjust `WorkingDirectory` and `ExecStart` if needed.

### 3. Run manually

```bash
python3 bisecur2mqtt.py
# or with a custom config:
BISECUR2MQTT_CONFIG=/path/to/bisecur2mqtt.conf python3 bisecur2mqtt.py
```

## MQTT interface

### Sending commands

Publish to: `bisecur2mqtt/send_command/command`

```bash
mosquitto_pub -h <broker> -t bisecur2mqtt/send_command/command -m impulse
```

#### Door commands

| Command | Description |
|---------|-------------|
| `impulse` | Trigger impulse (toggle) |
| `up` / `open` | Open the door |
| `down` / `close` | Close the door |
| `partial` | Partial open |
| `light` | Toggle light |
| `stop` | Stop mid-travel (reverses direction) |

#### Query commands

| Command | Description |
|---------|-------------|
| `position` | Publish current door position and state |
| `get_door_state` | Alias for `position` |
| `get_light_state` | Publish current light on/off state |
| `get_ports` | Publish gateway port/group list |
| `get_version` | Publish gateway firmware version |

#### Session / system commands

| Command | Description |
|---------|-------------|
| `login` | Re-authenticate with the gateway |
| `sys_restart` | Trigger gateway reconnect |
| `set_poll_interval <N>` | Set periodic position poll interval to N minutes at runtime (0 = disable) |
| `get_poll_interval` | Publish current poll interval to the response topic |

### Published topics

All door topics use the `door_name` subtopic (normalised to lowercase snake-case). With `door_name = 'Garage Door'` the topics are:

| Topic | Values | Notes |
|-------|--------|-------|
| `bisecur2mqtt/{door_name}/state` | `open`, `closed`, `opening`, `closing` | retained; updated on startup, after commands, and during travel |
| `bisecur2mqtt/{door_name}/position` | `0`–`100` (%) | updated on startup, dynamically during travel, and at steady state |
| `bisecur2mqtt/{door_name}/light` | `on`, `off` | updated on startup and after `light` command |
| `bisecur2mqtt/state` | `online`, `offline` | service availability (LWT) |
| `bisecur2mqtt/send_command/response` | text | result of last command |
| `bisecur2mqtt/attributes/gw_hw_version` | string | gateway firmware version |

Each topic also has a `_ts` variant with an ISO-8601 timestamp of the last update.

### Home Assistant autodiscovery

The service publishes a `cover` device config to the HA discovery topic on startup. Set `mqtt_topic_HA_discovery` in your config to match your HA MQTT discovery prefix (default: `homeassistant`).

## CLI tool

`bisecur_cli.py` connects directly to the gateway (no MQTT required). Each invocation opens a fresh session, sends the command, and disconnects.

```bash
python3 bisecur_cli.py [-c bisecur2mqtt.conf] [-v] <command>
```

| Command | Description |
|---------|-------------|
| `status` | Show firmware version, active ports, users, and groups |
| `position` | Query current door position |
| `impulse` | Send impulse command |
| `up` | Send open/up command |
| `down` | Send close/down command |
| `partial` | Send partial-open command |
| `light` | Toggle light |
| `login` | Connect and log in, print session token |
| `logout` | Connect, log in, then send clean logout |
| `cleanup` | Drain any stale gateway sessions, then logout |
| `port <id> [value]` | Send raw command to a port ID (value default: `0xFF`) |

Use `-v` to see full protocol debug output.

## Notes

- The gateway allows only one active session at a time. Running the CLI while `bisecur2mqtt.service` is running will disrupt the service session — use the MQTT interface, or stop the service first.
- Port commands (impulse, up, down, etc.) must be configured in the Hormann BiSecur mobile app before they will work. The gateway returns an error for unconfigured ports.
- The `legacy/` folder contains the original [pysecur3](https://github.com/skelsec/pysecur3) library this project originally depended on. It is kept for protocol reference only and is not used by current code.
