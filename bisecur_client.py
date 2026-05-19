"""
BiSecur Gateway MCP protocol client.

Replaces the unmaintained pysecur3 library with a clean, minimal implementation
of the Hormann BiSecur MCP protocol (TCP port 4000).

Wire format (all hex-encoded ASCII on the TCP socket):

  Outer packet:
    SRC_MAC(6B) + DST_MAC(6B) + MCP_PAYLOAD(LENGTH bytes) + PKT_CRC(1B)
    Encoded as: packet.hex().upper().encode()

  MCP payload (LENGTH bytes, LENGTH = total size including itself):
    LENGTH(2B) + TAG(1B) + TOKEN(4B) + CMD_ID(1B) + DATA + MCP_CRC(1B)

  CRC algorithms:
    PKT_CRC  = sum(ord(c) for c in hex_string.upper()) & 0xFF
    MCP_CRC  = (int.from_bytes(LENGTH_bytes, 'big') + sum(remaining_bytes)) & 0xFF
               (applied iteratively so intermediate results are also masked)
"""

import json
import logging
import socket
import threading
import time

log = logging.getLogger(__name__)


class BisecurError(Exception):
    pass


class BisecurGateway:
    """
    Thread-safe client for the Hormann BiSecur Gateway local MCP protocol.

    Public operations (get_door_position, set_door_state, etc.) acquire an
    internal lock so they are safe to call from multiple threads simultaneously.

    connect() and login() do NOT acquire the lock — call them from a
    single-threaded context (startup) or from reconnect() which already holds it.
    """

    # MCP command IDs (from pysecur3/MCP.py MCPCommand enum)
    CMD_PING             = 0
    CMD_ERROR            = 1
    CMD_JCMP             = 6
    CMD_GET_GW_VERSION   = 7
    CMD_LOGIN            = 16
    CMD_LOGOUT           = 17
    CMD_GET_USER_RIGHTS  = 40  # returns user_id + list of accessible port IDs
    CMD_GET_STATE        = 50  # returns current state byte for a port
    CMD_SET_STATE        = 51
    CMD_GET_PORT_NAME    = 52
    CMD_GET_TRANSITION   = 112  # HM_GET_TRANSITION

    def __init__(self, ip: str, gw_mac: str, src_mac: str = '000000000006',
                 port: int = 4000, timeout: float = 10.0,
                 debug_jcmp: bool = False, debug_packets: bool = False):
        self._ip            = ip
        self._port          = port
        self._timeout       = timeout
        self._src_mac       = bytes.fromhex(src_mac.replace(':', ''))
        self._gw_mac        = bytes.fromhex(gw_mac.replace(':', ''))
        self._sock: socket.socket | None = None
        self._buf           = b''
        self._tag           = 0
        self._token         = 0
        self._username: str | None = None
        self._password: str | None = None
        self._lock          = threading.Lock()
        self._debug_jcmp    = debug_jcmp
        self._debug_packets = debug_packets

    # ------------------------------------------------------------------ #
    # Lifecycle  (no lock — call from single-threaded context or reconnect)
    # ------------------------------------------------------------------ #

    def connect(self) -> None:
        """Open a TCP connection to the gateway (no login)."""
        self._close_socket()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self._timeout)
        s.connect((self._ip, self._port))
        self._sock = s
        self._buf  = b''
        log.info(f"Connected to BiSecur gateway {self._ip}:{self._port}")

    def login(self, username: str, password: str) -> None:
        """Authenticate and store the session token/tag."""
        self._username = username
        self._password = password
        data = len(username).to_bytes(1, 'big') + username.encode() + password.encode()
        resp = self._send_raw(self.CMD_LOGIN, data)
        # Gateway flushes stale sessions by sending LOGOUTs before the login response.
        # Drain up to 20 of them (halacs/BiSecur observed this in the wild).
        for _ in range(20):
            if resp['cmd_id'] != self.CMD_LOGOUT:
                break
            log.debug("Draining pre-login LOGOUT from gateway")
            resp = self._parse_response(self._read_packet())
        if len(resp['data']) < 5:
            raise BisecurError(f"Login response too short: {resp['data'].hex()}")
        self._tag   = resp['data'][0]
        self._token = int.from_bytes(resp['data'][1:5], 'big')
        log.info(f"Logged in as '{username}' (tag={self._tag}, token={self._token})")

    def logout(self) -> None:
        """Send a logout command, ignoring any errors."""
        try:
            self._send_raw(self.CMD_LOGOUT, b'')
        except Exception:
            pass
        self._tag   = 0
        self._token = 0

    def disconnect(self) -> None:
        """Log out and close the socket."""
        try:
            self.logout()
        except Exception:
            pass
        self._close_socket()

    def reconnect(self, max_delay: float = 60.0) -> None:
        """
        Reconnect with exponential backoff. Blocks until successful.
        Holds the lock only during each connection attempt; releases it
        during sleep so callers that check is_connected can return quickly.
        """
        delay = 1.0
        while True:
            with self._lock:
                try:
                    self.connect()
                    if self._username:
                        self.login(self._username, self._password)
                    return
                except Exception as e:
                    self._close_socket()
                    log.error(f"Reconnect to BiSecur gateway failed: {e}. Retrying in {delay:.0f}s")
            # Sleep outside the lock so other threads can observe is_connected == False
            time.sleep(delay)
            delay = min(delay * 2.0, max_delay)

    @property
    def is_connected(self) -> bool:
        return self._sock is not None

    # ------------------------------------------------------------------ #
    # Gateway operations  (lock acquired per call)
    # ------------------------------------------------------------------ #

    def get_gw_version(self) -> str:
        """Return the gateway firmware version string."""
        with self._lock:
            resp = self._send_recv(self.CMD_GET_GW_VERSION, b'\x00')
        return resp['data'].decode('utf-8', errors='replace').strip('\x00').strip()

    def get_door_position(self, port: int) -> int:
        """
        Return door position 0–100 (%), or -1 if the response is empty.
        The gateway encodes position as a raw byte 0–200 → 0–100%.
        """
        with self._lock:
            resp = self._send_recv(self.CMD_GET_TRANSITION, port.to_bytes(1, 'big'))
        if not resp['data']:
            return -1
        return round(resp['data'][0] / 2)

    def set_door_state(self, port: int, command_value: int = 0xFF) -> None:
        """
        Trigger a door action (impulse, up, down, partial, light, etc.).
        Payload is always two bytes: [port, command_value].
        """
        with self._lock:
            self._send_recv(self.CMD_SET_STATE, bytes([port, command_value & 0xFF]))

    def get_port_state(self, port_id: int) -> int | None:
        """
        Return the current state byte for a port (e.g. 0=off, 1=on for a light),
        or None if the gateway returns an error or empty data.
        """
        try:
            with self._lock:
                resp = self._send_recv(self.CMD_GET_STATE, bytes([port_id]))
        except BisecurError:
            return None
        if not resp['data']:
            return None
        return resp['data'][0]

    def get_user_rights(self) -> list[int]:
        """
        Return the list of port IDs the current user has access to.
        Response: user_id (1 byte) + port_ids (1 byte each).
        """
        with self._lock:
            resp = self._send_recv(self.CMD_GET_USER_RIGHTS, b'\x00')
        return list(resp['data'][1:])  # skip leading user_id byte

    def get_port_name(self, port_id: int) -> str | None:
        """
        Return the name string configured for a port, or None if the gateway
        returns an error or empty data for that port ID.
        """
        try:
            with self._lock:
                resp = self._send_recv(self.CMD_GET_PORT_NAME, bytes([port_id]))
        except BisecurError:
            return None
        if not resp['data']:
            return None
        return resp['data'].decode('utf-8', errors='replace').strip('\x00').strip()

    def jcmp(self, payload: dict) -> dict:
        """Send an arbitrary JCMP JSON command and return the parsed response dict."""
        cmd = json.dumps(payload, separators=(',', ':'))
        if self._debug_jcmp:
            log.info(f"JCMP >> {cmd}")
        with self._lock:
            resp = self._send_recv(self.CMD_JCMP, cmd.encode())
        result = json.loads(resp['data'])
        if self._debug_jcmp:
            log.info(f"JCMP << {json.dumps(result)}")
        return result

    # ------------------------------------------------------------------ #
    # Internal helpers  (no lock — callers are responsible)
    # ------------------------------------------------------------------ #

    def _close_socket(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
            self._buf  = b''

    def _calc_mcp_crc(self, buf: bytes) -> int:
        """
        MCP payload CRC.
        Start = LENGTH field (buf[:2]) as uint16, then add each subsequent
        byte with an 8-bit mask at each step.
        """
        cks = int.from_bytes(buf[:2], 'big')
        for b in buf[2:]:
            cks = (cks + b) & 0xFF
        return cks & 0xFF

    def _calc_packet_crc(self, buf: bytes) -> int:
        """Outer packet CRC: sum of ASCII ordinals of the upper-hex string, mod 256."""
        return sum(ord(c) for c in buf.hex().upper()) & 0xFF

    def _build_packet(self, cmd_id: int, data: bytes) -> bytes:
        """
        Build a complete hex-encoded MCP packet ready for the TCP socket.

        MCP payload layout (LENGTH bytes, LENGTH = 9 + len(data)):
          LENGTH(2) + TAG(1) + TOKEN(4) + CMD_ID(1) + DATA + MCP_CRC(1)

        Outer packet:
          SRC_MAC(6) + DST_MAC(6) + MCP_PAYLOAD + PKT_CRC(1)  → .hex().upper().encode()
        """
        inner   = (self._tag.to_bytes(1, 'big') + self._token.to_bytes(4, 'big')
                   + cmd_id.to_bytes(1, 'big') + data)
        length  = len(inner) + 3   # = 9 + len(data): LENGTH(2) + inner + CRC(1) total
        mcp_buf = length.to_bytes(2, 'big') + inner
        mcp_pl  = mcp_buf + self._calc_mcp_crc(mcp_buf).to_bytes(1, 'big')
        packet  = self._src_mac + self._gw_mac + mcp_pl
        full    = packet + self._calc_packet_crc(packet).to_bytes(1, 'big')
        return full.hex().upper().encode()

    def _read_packet(self) -> bytes:
        """
        Read one complete packet from the socket, accumulating hex-encoded ASCII
        bytes in self._buf. Returns decoded raw bytes (not hex).
        """
        # Need ≥28 ASCII chars to decode first 14 bytes: SRC_MAC(6)+DST_MAC(6)+LENGTH(2)
        while len(self._buf) < 28:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise ConnectionError("BiSecur gateway closed the connection")
            self._buf += chunk

        # Extract LENGTH: bytes 12–13 of the actual packet = ASCII chars 24–27
        length = int.from_bytes(bytes.fromhex(self._buf[:28].decode())[12:14], 'big')

        # Full packet = SRC_MAC(6)+DST_MAC(6)+MCP_PAYLOAD(LENGTH)+PKT_CRC(1) = 13+LENGTH bytes
        # → (13+LENGTH)*2 ASCII chars
        total_chars = (13 + length) * 2

        while len(self._buf) < total_chars:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise ConnectionError("BiSecur gateway closed connection mid-packet")
            self._buf += chunk

        raw       = bytes.fromhex(self._buf[:total_chars].decode())
        self._buf = self._buf[total_chars:]
        return raw

    def _parse_response(self, packet: bytes) -> dict:
        """
        Verify CRCs and parse a raw packet.
        Returns {'cmd_id': int, 'is_response': bool, 'data': bytes}.
        Raises BisecurError on CRC failure or gateway error responses.
        """
        if packet[-1] != self._calc_packet_crc(packet[:-1]):
            raise BisecurError("Outer packet CRC mismatch")

        # MCP payload: strip SRC_MAC(6), DST_MAC(6), and trailing PKT_CRC(1)
        mcp = packet[12:-1]
        if mcp[-1] != self._calc_mcp_crc(mcp[:-1]):
            raise BisecurError("MCP payload CRC mismatch")

        cmd_raw     = mcp[7]
        is_response = bool(cmd_raw & 0x80)
        cmd_id      = cmd_raw & 0x7F
        data        = mcp[8:-1]

        # This gateway sends CMD_ERROR without the is_response bit; check both ways.
        if cmd_id == self.CMD_ERROR and data:
            raise BisecurError(f"Gateway returned error code {data[0]}")

        return {'cmd_id': cmd_id, 'is_response': is_response, 'data': data}

    def _send_raw(self, cmd_id: int, data: bytes) -> dict:
        """Send a packet and parse the response. No lock — caller is responsible."""
        pkt = self._build_packet(cmd_id, data)
        if self._debug_packets:
            log.info(f"PKT >> cmd={cmd_id} {pkt.decode()}")
        self._sock.sendall(pkt)
        raw = self._read_packet()
        if self._debug_packets:
            log.info(f"PKT << {raw.hex().upper()}")
        return self._parse_response(raw)

    def _send_recv(self, cmd_id: int, data: bytes = b'') -> dict:
        """
        Send a command and receive the response.

        Distinguishes two failure modes:
          - socket.timeout: the gateway did not respond within self._timeout.
            The TCP connection may still be alive (gateway ignoring the command).
            Raises BisecurError without closing the socket.
          - other OSError: genuine I/O failure (broken pipe, connection reset, etc.)
            Closes the socket and raises ConnectionError.

        Callers must hold self._lock.
        """
        if self._sock is None:
            raise ConnectionError("Not connected to BiSecur gateway")
        try:
            resp = self._send_raw(cmd_id, data)
        except socket.timeout:
            # Do not close the socket — connection may still be alive.
            raise BisecurError(f"Command {cmd_id} timed out (no response from gateway)")
        except OSError as e:
            log.error(f"BiSecur gateway I/O error on cmd {cmd_id}: {e}")
            self._close_socket()
            raise ConnectionError(f"BiSecur gateway I/O failed: {e}") from e

        # An unsolicited LOGOUT from the gateway terminates the session.
        # (login() calls _send_raw directly and handles the expected pre-login LOGOUT itself.)
        if resp['cmd_id'] == self.CMD_LOGOUT:
            self._close_socket()
            raise ConnectionError("Gateway terminated the session (unsolicited LOGOUT)")

        return resp
