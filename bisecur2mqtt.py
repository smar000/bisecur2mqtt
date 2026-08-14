import ast
import json
import logging as log
import logging.handlers
import os
import signal
import sys
import threading
import time
from datetime import datetime

import paho.mqtt.client as paho
from paho.mqtt.enums import CallbackAPIVersion

from bisecur_client import BisecurError, BisecurGateway

VERSION = "1.1.0"

CONFIG_FILE = os.getenv('BISECUR2MQTT_CONFIG', 'bisecur2mqtt.conf')

# ------------------------------------------------------------------ #
# Configuration loader
# ------------------------------------------------------------------ #

class Config:
    """
    Load a Python-literal key=value config file safely using ast.parse.
    Only simple assignment statements with literal right-hand sides are read;
    comments, blank lines, and any other constructs are silently ignored.
    Compatible with the existing bisecur2mqtt.conf format.
    """
    def __init__(self, filename: str = CONFIG_FILE):
        self._data: dict = {}
        with open(filename, encoding='utf-8') as f:
            source = f.read()
        tree = ast.parse(source, filename=filename, mode='exec')
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        try:
                            self._data[target.id] = ast.literal_eval(node.value)
                        except (ValueError, TypeError):
                            pass  # skip non-literal values

    def get(self, key: str, default=None):
        return self._data.get(key, default)


try:
    config = Config()
except Exception as e:
    print(f"Cannot load config from '{CONFIG_FILE}': {e}", file=sys.stderr)
    sys.exit(2)


# ------------------------------------------------------------------ #
# Logging
# ------------------------------------------------------------------ #

LOG_DIR        = config.get('log_dir', '.')
LOG_MAX_MB     = float(config.get('log_max_size_mb', 10))
LOG_BACKUPS    = int(config.get('log_backup_count', 5))
LOGFORMAT      = "%(asctime)s [%(filename)s:%(lineno)3d]  %(levelname)s  %(message)s"
DEBUG          = bool(config.get('debug', False))
DEBUG_JCMP     = bool(config.get('debug_jcmp', False))
DEBUG_PACKETS  = bool(config.get('debug_packets', False))

_script_stem = os.path.splitext(os.path.basename(__file__))[0]
LOGFILE      = os.path.join(LOG_DIR, f"{_script_stem}.log")

os.makedirs(LOG_DIR, exist_ok=True)
_root = log.getLogger()
_root.setLevel(log.DEBUG if DEBUG else log.INFO)
_fh = logging.handlers.RotatingFileHandler(
    LOGFILE,
    maxBytes=int(LOG_MAX_MB * 1024 * 1024),
    backupCount=LOG_BACKUPS,
)
_fh.setFormatter(log.Formatter(LOGFORMAT))
_root.addHandler(_fh)
_root.addHandler(log.StreamHandler())

log.info(f"bisecur2mqtt v{VERSION} starting")


# ------------------------------------------------------------------ #
# MQTT / gateway globals
# ------------------------------------------------------------------ #

MQTT_TOPIC_BASE      = config.get("mqtt_topic_base", "bisecur2mqtt")
MQTT_COMMAND_SUBTOPIC = "send_command"
MQTT_QOS             = 0

COMMAND_DELAY_SECONDS = float(config.get("command_delay_seconds", 0.5))  # Rate limiting

mqtt_client: paho.Client | None = None
gateway: BisecurGateway | None  = None

# ------------------------------------------------------------------ #
# Door state  (shared between MQTT callback thread and tracking thread)
# ------------------------------------------------------------------ #

_state_lock          = threading.Lock()
_last_door_state: str | None = None

_pos_stop_event      = threading.Event()
_pos_tracking_thread: threading.Thread | None = None

_periodic_stop_event  = threading.Event()
_periodic_poll_thread: threading.Thread | None = None
_poll_interval_min: float = 15.0   # authoritative runtime value; updated by set_poll_interval

_reconnect_in_progress = False
_reconnect_lock        = threading.Lock()

# Port map: action name → gateway port number
_ports: dict[str, int] = {}

# Port used for position queries (HM_GET_TRANSITION).
# Initialised to 0; overridden at startup with impulse_port (or position_port if configured).
_pos_port: int = 0

# MQTT subtopic used for all door state/position/light messages.
# Resolved at startup from gateway group name, config door_name, or "default_door".
_door_topic: str = "default_door"

# Gateway health check: count consecutive query failures
# (The gateway firmware has a known bug where it becomes unresponsive and requires reboot)
_gw_query_failures: int = 0
_GW_FAILURE_THRESHOLD: int = 5  # Alert after 5 consecutive failures

# Command rate limiting: track last command time
_last_command_time: float = 0.0


# ------------------------------------------------------------------ #
# MQTT helper
# ------------------------------------------------------------------ #

def publish(topic: str, payload, topic_base: str | None = None,
            retain: bool = False, ts_only: bool = False) -> None:
    if mqtt_client is None:
        return
    if topic_base is None:
        topic_base = MQTT_TOPIC_BASE
    if not isinstance(payload, str):
        payload = str(payload)
    try:
        if not ts_only:
            log.debug(f"MQTT pub: {topic_base}/{topic} = {payload!r}")
            mqtt_client.publish(f"{topic_base}/{topic}", payload,
                                qos=MQTT_QOS, retain=retain)
        ts = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        mqtt_client.publish(f"{topic_base}/{topic}_ts", ts,
                            qos=MQTT_QOS, retain=retain)
    except Exception as e:
        log.error(f"MQTT publish error ({topic_base}/{topic}): {e}")


# ------------------------------------------------------------------ #
# Reconnect
# ------------------------------------------------------------------ #

def _trigger_reconnect() -> None:
    """Start a background reconnect thread if one is not already running."""
    global _reconnect_in_progress
    with _reconnect_lock:
        if _reconnect_in_progress:
            return
        _reconnect_in_progress = True

    def _worker():
        global _reconnect_in_progress
        try:
            log.info("Gateway reconnect starting…")
            gateway.reconnect()
            log.info("Gateway reconnected successfully")
            publish("state", "online", retain=True)
        except Exception as e:
            log.error(f"Gateway reconnect worker error: {e}")
        finally:
            with _reconnect_lock:
                _reconnect_in_progress = False

    threading.Thread(name='reconnect', target=_worker, daemon=True).start()


# ------------------------------------------------------------------ #
# Gateway operations
# ------------------------------------------------------------------ #

def _update_door_status() -> tuple[int, str]:
    """
    Poll the gateway for current door position/state and publish to MQTT.
    Returns (position, state) or (-1, 'unknown') on failure.

    Note: The gateway may intermittently become unresponsive (known firmware issue).
    When this happens, position queries fail with PORT_ERROR even though ports exist.
    A gateway reboot usually restores functionality.
    """
    global _last_door_state, _gw_query_failures

    try:
        pos = gateway.get_door_position(_pos_port)
        # Query succeeded — reset failure counter
        if _gw_query_failures > 0:
            log.info(f"Gateway responsive again (recovered after {_gw_query_failures} failures)")
            publish("attributes/gateway_health", "ok")
            _gw_query_failures = 0
    except ConnectionError as e:
        log.error(f"get_door_position failed (connection lost): {e}")
        _trigger_reconnect()
        return -1, "unknown"
    except BisecurError as e:
        _gw_query_failures += 1
        if _gw_query_failures == 1:
            log.error(f"get_door_position failed (port {_pos_port}): {e}")
        if _gw_query_failures >= _GW_FAILURE_THRESHOLD:
            msg = (f"Gateway unresponsive ({_gw_query_failures} consecutive failures). "
                   f"This is a known firmware bug — try rebooting the gateway.")
            log.error(msg)
            publish("attributes/gateway_health", "unresponsive", retain=True)
        return -1, "unknown"

    if pos < 0:
        log.warning("get_door_position returned -1 (no data from gateway)")
        return -1, "unknown"

    if pos == 0:
        state = "closed"
    elif pos == 100:
        state = "open"
    else:
        state = "unknown"   # mid-travel — only track_door_position refines this

    with _state_lock:
        _last_door_state = state

    publish(f"{_door_topic}/position", pos)
    if state in ("open", "closed"):
        publish(f"{_door_topic}/state", state, retain=True)

    log.info(f"Door: {pos}% ({state})")
    return pos, state


def _do_door_action(action: str) -> str:
    """
    Send a door command to the gateway and start position tracking.
    Returns a human-readable result string.

    Enforces a minimum delay between commands to prevent gateway rate limiting
    (which can cause the gateway to become unresponsive).
    """
    global _last_door_state, _pos_tracking_thread, _pos_stop_event, _last_command_time

    # Enforce command rate limiting
    now = time.time()
    time_since_last = now - _last_command_time
    if time_since_last < COMMAND_DELAY_SECONDS:
        delay = COMMAND_DELAY_SECONDS - time_since_last
        log.debug(f"Rate limiting: waiting {delay:.2f}s before next command")
        time.sleep(delay)
        _last_command_time = time.time()
    else:
        _last_command_time = now

    if action == "stop":
        with _state_lock:
            current = _last_door_state
        if current == "opening":
            action = "down"
        elif current == "closing":
            action = "up"
        else:
            msg = f"Ignoring 'stop': door direction unknown (state={current!r})"
            log.warning(msg)
            return msg

    port = _ports.get(action)
    if port is None:
        msg = f"No port configured for action '{action}'"
        log.error(msg)
        return msg

    try:
        gateway.set_door_state(port)
        log.info(f"Door action '{action}' sent (port {port})")
    except ConnectionError as e:
        log.error(f"Door action '{action}' failed (connection lost): {e}")
        _trigger_reconnect()
        return str(e)
    except BisecurError as e:
        log.error(f"Door action '{action}' rejected by gateway: {e}")
        return str(e)

    # Stop any existing tracking thread
    _pos_stop_event.set()
    if _pos_tracking_thread and _pos_tracking_thread.is_alive():
        _pos_tracking_thread.join(timeout=3.0)

    # Start fresh tracking
    _pos_stop_event = threading.Event()
    _pos_tracking_thread = threading.Thread(
        name='pos_tracking',
        target=_track_door_position,
        args=(action, _pos_stop_event),
        daemon=True,
    )
    _pos_tracking_thread.start()
    return f"Action '{action}' sent"


def _track_door_position(action: str, stop_event: threading.Event) -> None:
    """
    Background thread: poll door position every second and publish until stable.
    Stops when the door reaches open/closed, on error, or when stop_event is set.
    Does a final confirmed read once the door settles.
    """
    global _last_door_state
    last_pos = -1
    door_settled = False
    error_count = 0

    while not stop_event.wait(1.0):
        try:
            pos = gateway.get_door_position(_pos_port)
        except ConnectionError as e:
            log.warning(f"Position tracking — connection lost: {e}")
            break
        except BisecurError as e:
            error_count += 1
            if error_count == 1:  # Log the first error, then less frequently
                log.warning(f"Position tracking — query failed (port {_pos_port}): {e}")
            elif error_count % 10 == 0:
                log.debug(f"Position tracking — query still failing ({error_count} errors)")
            continue

        error_count = 0  # Reset error counter when query succeeds

        if pos < 0:
            log.warning(f"Position tracking — no data from gateway (port {_pos_port})")
            break

        if last_pos == -1:
            # First reading — no direction known yet.
            if pos == 100:
                state = "open"
            elif pos == 0:
                state = "closed"
            else:
                state = "unknown"
        elif pos < last_pos:
            state = "closing"
        elif pos > last_pos:
            state = "opening"
        elif pos == 100:
            state = "open"
        elif pos == 0:
            state = "closed"
        else:
            state = "unknown"

        with _state_lock:
            _last_door_state = state

        publish(f"{_door_topic}/position", pos)
        publish(f"{_door_topic}/state", state, retain=True)
        log.debug(f"Tracking: {pos}% ({state})")

        last_pos = pos

        if state in ("open", "closed"):
            door_settled = True
            break

    log.debug("Position tracking ended")

    # One final confirmed read once the door has settled, to publish steady-state.
    if door_settled:
        _update_door_status()


def _update_light_status() -> None:
    """Poll the light port state and publish to MQTT."""
    light_port = _ports.get("light")
    if light_port is None:
        return
    try:
        raw = gateway.get_port_state(light_port)
    except ConnectionError as e:
        log.warning(f"get_light_state failed (connection lost): {e}")
        _trigger_reconnect()
        return
    if raw is None:
        log.debug("Light state: no data returned by gateway")
        return
    label = "on" if raw else "off"
    publish(f"{_door_topic}/light", label)
    log.info(f"Light state: {label} (raw={raw})")


# ------------------------------------------------------------------ #
# Periodic position poll
# ------------------------------------------------------------------ #

def _restart_periodic_poll(new_interval_min: float) -> None:
    """Stop any running periodic poll thread and start a fresh one at new_interval_min."""
    global _periodic_stop_event, _periodic_poll_thread, _poll_interval_min

    _poll_interval_min = new_interval_min

    _periodic_stop_event.set()
    if _periodic_poll_thread and _periodic_poll_thread.is_alive():
        _periodic_poll_thread.join(timeout=5.0)

    _periodic_stop_event = threading.Event()

    if new_interval_min > 0:
        _periodic_poll_thread = threading.Thread(
            name='periodic_poll',
            target=_periodic_poll_worker,
            args=(new_interval_min * 60, _periodic_stop_event),
            daemon=True,
        )
        _periodic_poll_thread.start()
        log.info(f"Periodic poll restarted at {new_interval_min:.4g} min")
    else:
        _periodic_poll_thread = None
        log.info("Periodic poll disabled")

    publish(f"attributes/poll_interval_min", str(new_interval_min))


def _periodic_poll_worker(interval_s: float, stop_event: threading.Event) -> None:
    """
    Background thread: poll door position every interval_s seconds.
    Skips a poll cycle if a door-action tracking thread is currently active.
    """
    log.info(f"Periodic position poll started (interval={interval_s:.0f}s)")
    while not stop_event.wait(interval_s):
        if _pos_tracking_thread and _pos_tracking_thread.is_alive():
            log.debug("Periodic poll skipped — door tracking in progress")
            continue
        if not gateway.is_connected:
            log.debug("Periodic poll skipped — gateway not connected")
            continue
        log.debug("Periodic poll: refreshing door position")
        _update_door_status()
    log.debug("Periodic position poll stopped")


# ------------------------------------------------------------------ #
# Command dispatcher
# ------------------------------------------------------------------ #

def do_command(cmd: str) -> None:
    """Dispatch an incoming MQTT command to the appropriate gateway operation."""
    publish(f"{MQTT_COMMAND_SUBTOPIC}/command", datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
            ts_only=True)

    if not gateway.is_connected:
        resp = "Gateway not connected — reconnecting…"
        log.warning(f"Command '{cmd}' received while disconnected, triggering reconnect")
        publish(f"{MQTT_COMMAND_SUBTOPIC}/response", resp)
        _trigger_reconnect()
        return

    resp = ""
    try:
        if cmd in ("get_door_state", "get_door_position", "position"):
            pos, state = _update_door_status()
            resp = f"position={pos}, state={state}"

        elif cmd == "get_light_state":
            _update_light_status()
            resp = "Light state updated"

        elif cmd == "light":
            port = _ports.get("light")
            if port is None:
                resp = "No light_port configured"
            else:
                try:
                    gateway.set_door_state(port)
                    resp = "Light toggled"
                    threading.Timer(1.5, _update_light_status).start()
                except ConnectionError as e:
                    log.error(f"Light command failed (connection lost): {e}")
                    _trigger_reconnect()
                    resp = str(e)
                except BisecurError as e:
                    log.error(f"Light command rejected by gateway: {e}")
                    resp = str(e)

        elif cmd in ("up", "down", "open", "close", "stop", "impulse", "partial"):
            sanitised = {"open": "up", "close": "down"}.get(cmd, cmd)
            resp = _do_door_action(sanitised)

        elif cmd == "get_ports":
            try:
                ports = gateway.jcmp({'CMD': 'GET_GROUPS'})
                resp = json.dumps(ports)
                publish("attributes/user0_ports", resp)
                log.info(f"Ports: {json.dumps(ports, indent=2)}")
            except ConnectionError as e:
                resp = str(e)
                _trigger_reconnect()
            except BisecurError as e:
                resp = str(e)

        elif cmd in ("get_version", "get_gw_version"):
            try:
                version = gateway.get_gw_version()
                resp = version
                publish("attributes/gw_hw_version", version)
                log.info(f"Gateway version: {version}")
            except ConnectionError as e:
                resp = str(e)
                _trigger_reconnect()
            except BisecurError as e:
                resp = str(e)

        elif cmd == "login":
            try:
                gateway.login(config.get("bisecur_user"), config.get("bisecur_pw"))
                resp = "Login successful"
            except (ConnectionError, BisecurError) as e:
                resp = str(e)

        elif cmd in ("sys_restart", "init_bisecur_gw"):
            _trigger_reconnect()
            resp = "Reconnect triggered"

        elif cmd.startswith("set_poll_interval"):
            parts = cmd.split()
            if len(parts) != 2:
                resp = "Usage: set_poll_interval <minutes>"
            else:
                try:
                    new_val = float(parts[1])
                    if new_val < 0:
                        raise ValueError("interval must be >= 0")
                    _restart_periodic_poll(new_val)
                    resp = f"Poll interval set to {new_val:.4g} min" if new_val > 0 else "Periodic poll disabled"
                    log.info(f"set_poll_interval: {resp}")
                except ValueError as e:
                    resp = f"Invalid value: {e}"
                    log.warning(f"set_poll_interval bad value: {e}")

        elif cmd == "get_poll_interval":
            resp = f"poll_interval_min={_poll_interval_min:.4g}"

        else:
            resp = f"Unknown command: '{cmd}'"
            log.warning(resp)

    except Exception as e:
        log.exception(f"Unhandled error in do_command('{cmd}')")
        resp = str(e)

    publish(f"{MQTT_COMMAND_SUBTOPIC}/response", resp)


# ------------------------------------------------------------------ #
# Home Assistant discovery
# ------------------------------------------------------------------ #

def init_ha_discovery() -> None:
    bisecur_mac = config.get("bisecur_mac", "").replace(':', '')
    bisecur_ip  = config.get("bisecur_ip", "")

    gw_version = ""
    try:
        gw_version = gateway.get_gw_version()
        log.info(f"Gateway version: {gw_version}")
        publish("attributes/gw_hw_version", gw_version)
    except Exception as e:
        log.warning(f"Could not read gateway version: {e}")

    ha_payload = {
        "name":                  "Garage Door",
        "unique_id":             f"bisecur_{bisecur_mac}",
        "device_class":          "garage",
        "schema":                "state",
        "command_topic":         f"{MQTT_TOPIC_BASE}/{MQTT_COMMAND_SUBTOPIC}/command",
        "state_topic":           f"{MQTT_TOPIC_BASE}/{_door_topic}/state",
        "payload_open":          "up",
        "payload_close":         "down",
        "payload_stop":          "impulse",
        "position_topic":        f"{MQTT_TOPIC_BASE}/{_door_topic}/position",
        "position_open":         100,
        "position_closed":       0,
        "availability_topic":    f"{MQTT_TOPIC_BASE}/state",
        "payload_available":     "online",
        "payload_not_available": "offline",
        "device": {
            "identifiers":  [f"bisecur_{bisecur_mac}"],
            "name":         "BiSecur Gateway",
            "manufacturer": "Hormann",
            "model":        "BiSecur Gateway",
            "sw_version":   VERSION,
            "hw_version":   gw_version,
            "connections":  [["mac", bisecur_mac], ["ip", bisecur_ip]],
        },
    }

    ha_base = config.get("mqtt_topic_HA_discovery", "homeassistant")
    publish("cover/bisecur/config", json.dumps(ha_payload), topic_base=ha_base, retain=True)
    publish("attributes/system_version", VERSION)
    publish("attributes/gw_ip_address", bisecur_ip)
    publish("attributes/gw_mac_address", bisecur_mac)
    log.info("HA discovery payload published")


# ------------------------------------------------------------------ #
# MQTT callbacks
# ------------------------------------------------------------------ #

_mqtt_connected = threading.Event()


def on_connect(client, userdata, flags, reason_code, properties):
    if reason_code.is_failure:
        log.error(f"MQTT connect failed: {reason_code}")
        return
    sub_topic = f"{MQTT_TOPIC_BASE}/{MQTT_COMMAND_SUBTOPIC}/command"
    log.info(f"Connected to MQTT broker. Subscribing to '{sub_topic}'")
    client.subscribe(sub_topic, MQTT_QOS)
    publish("state", "online", retain=True)
    _mqtt_connected.set()


def on_disconnect(client, userdata, disconnect_flags, reason_code, properties):
    log.info(f"Disconnected from MQTT broker (rc={reason_code})")
    _mqtt_connected.clear()


def on_message(client, userdata, msg):
    cmd = msg.payload.decode('utf-8', errors='replace').lower().strip()
    log.info(f"Received '{cmd}' on '{msg.topic}'")
    do_command(cmd)


# ------------------------------------------------------------------ #
# Entry point
# ------------------------------------------------------------------ #

if __name__ == '__main__':

    # --- Validate config ---
    bisecur_ip  = config.get("bisecur_ip")
    bisecur_mac = config.get("bisecur_mac")
    bisecur_user = config.get("bisecur_user")
    bisecur_pw   = config.get("bisecur_pw")
    src_mac      = config.get("src_mac", "FF:FF:FF:FF:FF:FF")

    if not (bisecur_ip and bisecur_mac):
        log.error("bisecur_ip and bisecur_mac must be set in config")
        sys.exit(2)

    # --- Load port map ---
    for action in ("impulse", "up", "down", "partial", "light"):
        port_val = config.get(f"{action}_port")
        if isinstance(port_val, int):
            _ports[action] = port_val

    if "impulse" not in _ports:
        log.error("impulse_port must be set in config (integer)")
        sys.exit(2)

    _pos_port = _ports["impulse"]  # default: all ports return overall door position
    pos_port_cfg = config.get("position_port")
    if isinstance(pos_port_cfg, int):
        _pos_port = pos_port_cfg

    log.info(f"Port map: {_ports}, position_port: {_pos_port}")

    # Resolve door subtopic: gateway group name → config door_name → "default_door"
    def _resolve_door_topic() -> str:
        def slugify(s: str) -> str:
            return s.strip().lower().replace(' ', '_')

        try:
            groups = gateway.jcmp({'CMD': 'GET_GROUPS'})
            if groups and isinstance(groups, list):
                name = groups[0].get('name', '').strip()
                if name:
                    slug = slugify(name)
                    log.info(f"Door topic from gateway group: '{slug}'")
                    return slug
        except Exception as e:
            log.warning(f"Could not read groups for door topic: {e}")

        return slugify(config.get("door_name", "default_door"))

    # --- Connect to BiSecur gateway ---
    gateway = BisecurGateway(
        ip             = bisecur_ip,
        gw_mac         = bisecur_mac,
        src_mac        = src_mac,
        timeout        = float(config.get("bisecur_timeout", 10)),
        debug_jcmp     = DEBUG_JCMP,
        debug_packets  = DEBUG_PACKETS,
    )

    log.info(f"Connecting to BiSecur gateway {bisecur_ip}…")
    try:
        gateway.connect()
        gateway.login(bisecur_user, bisecur_pw)
    except Exception as e:
        log.error(f"Could not connect to BiSecur gateway: {e}")
        sys.exit(2)

    # --- Connect to MQTT broker ---
    clientid = config.get('mqtt_client_id', f'bisecur2mqtt-{os.getpid()}')
    mqtt_client = paho.Client(
        CallbackAPIVersion.VERSION2,
        client_id=clientid,
        clean_session=False,
    )
    mqtt_client.will_set(f"{MQTT_TOPIC_BASE}/state", "offline", qos=0, retain=True)
    mqtt_client.on_connect    = on_connect
    mqtt_client.on_disconnect = on_disconnect
    mqtt_client.on_message    = on_message

    if config.get('mqtt_username') is not None:
        mqtt_client.username_pw_set(config.get('mqtt_username'), config.get('mqtt_password'))

    if config.get('mqtt_tls') is not None:
        mqtt_client.tls_set()

    broker = config.get('mqtt_broker', 'localhost')
    port   = int(config.get('mqtt_port', 1883))
    log.info(f"Connecting to MQTT broker {broker}:{port}…")
    mqtt_client.connect(broker, port, keepalive=60)
    mqtt_client.loop_start()

    # Wait for MQTT connection (up to 15 s)
    if not _mqtt_connected.wait(timeout=15.0):
        log.warning("MQTT connection not confirmed within 15s — continuing anyway")

    # --- Resolve door topic and publish HA discovery ---
    _door_topic = _resolve_door_topic()
    log.info(f"Door topic: '{_door_topic}'")

    init_ha_discovery()

    # Publish initial position and light state.
    _update_door_status()
    _update_light_status()

    # --- Start periodic position poll ---
    _restart_periodic_poll(float(config.get("position_poll_interval", 15)))

    # --- Run until SIGTERM / SIGINT ---
    shutdown_event = threading.Event()

    def _shutdown(signum=None, frame=None):
        log.info(f"Shutdown signal received ({signum})")
        shutdown_event.set()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT,  _shutdown)

    log.info("Service running")
    shutdown_event.wait()

    # --- Graceful shutdown ---
    log.info("Shutting down…")
    _periodic_stop_event.set()
    _pos_stop_event.set()
    if _periodic_poll_thread and _periodic_poll_thread.is_alive():
        _periodic_poll_thread.join(timeout=5.0)
    if _pos_tracking_thread and _pos_tracking_thread.is_alive():
        _pos_tracking_thread.join(timeout=3.0)

    publish("state", "offline", retain=True)
    time.sleep(0.5)   # let the publish flush

    mqtt_client.loop_stop()
    mqtt_client.disconnect()

    gateway.disconnect()
    log.info("Shutdown complete")
