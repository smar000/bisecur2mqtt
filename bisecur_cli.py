#!/usr/bin/env python3
"""
bisecur_cli.py - Command-line tool for the BiSecur gateway.

Usage:
  bisecur_cli.py [-c FILE] [-v] <command> [args]

Commands:
  login               Connect and log in; print session tag/token
  logout              Log in then send a clean logout
  cleanup             Log in (drains any stale gateway sessions) then logout
  position            Query current door position (uses position_port from config)
  impulse             Trigger impulse on configured port
  up                  Send 'up' command on configured port
  down                Send 'down' command on configured port
  partial             Send 'partial open' command on configured port
  light               Toggle light on configured port
  port <id> [value]   Send a command to a raw port ID (value default: 0xFF)
  status              Show firmware version, ports, users, and groups
"""

import argparse
import ast
import json
import logging
import os
import sys

from bisecur_client import BisecurError, BisecurGateway

CONFIG_FILE = os.getenv('BISECUR2MQTT_CONFIG', 'bisecur2mqtt.conf')

NAMED_ACTIONS = ('impulse', 'up', 'down', 'partial', 'light')


# ------------------------------------------------------------------ #
# Config loader (same safe ast.literal_eval approach as main service)
# ------------------------------------------------------------------ #

def load_config(path: str) -> dict:
    cfg: dict = {}
    with open(path, encoding='utf-8') as f:
        tree = ast.parse(f.read(), filename=path, mode='exec')
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    try:
                        cfg[target.id] = ast.literal_eval(node.value)
                    except (ValueError, TypeError):
                        pass
    return cfg


# ------------------------------------------------------------------ #
# Argument parsing
# ------------------------------------------------------------------ #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description='BiSecur gateway command-line tool',
    )
    p.add_argument('-c', '--config', default=CONFIG_FILE,
                   help=f'Config file (default: {CONFIG_FILE})')
    p.add_argument('-v', '--verbose', action='store_true',
                   help='Show DEBUG-level protocol output')

    sub = p.add_subparsers(dest='command', metavar='command')
    sub.required = True

    sub.add_parser('login',    help='Connect and log in')
    sub.add_parser('logout',   help='Log in then send a clean logout')
    sub.add_parser('cleanup',  help='Drain stale gateway sessions then logout')
    sub.add_parser('position', help='Query current door position')
    sub.add_parser('status',   help='Show firmware version, ports, users, and groups')

    for action in NAMED_ACTIONS:
        sub.add_parser(action, help=f"Send '{action}' command to configured port")

    port_cmd = sub.add_parser('port', help='Send command to a raw port ID')
    port_cmd.add_argument('port_id', type=int, help='Port ID (0-based integer)')
    port_cmd.add_argument('cmd_value', nargs='?', default=0xFF,
                          type=lambda x: int(x, 0),
                          help='Command value (default: 0xFF)')

    return p


# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #

def connect_and_login(cfg: dict) -> BisecurGateway:
    gw = BisecurGateway(
        ip      = cfg['bisecur_ip'],
        gw_mac  = cfg['bisecur_mac'],
        src_mac = cfg.get('src_mac', 'FF:FF:FF:FF:FF:FF'),
        timeout = float(cfg.get('bisecur_timeout', 10)),
    )
    gw.connect()
    gw.login(cfg['bisecur_user'], cfg['bisecur_pw'])
    return gw


def port_for_action(cfg: dict, action: str) -> int:
    key = f'{action}_port'
    port = cfg.get(key)
    if not isinstance(port, int):
        print(f"Error: '{key}' not set in config.", file=sys.stderr)
        sys.exit(1)
    return port


# ------------------------------------------------------------------ #
# Command handlers
# ------------------------------------------------------------------ #

def cmd_login(cfg: dict, _args) -> None:
    gw = connect_and_login(cfg)
    # Access internal state just for display; no public getter needed in a CLI.
    print(f"Logged in  tag={gw._tag}  token={gw._token}")
    # Leave session open — demonstrates a persistent login without acting further.
    gw.disconnect()


def cmd_logout(cfg: dict, _args) -> None:
    gw = connect_and_login(cfg)
    gw.logout()
    gw._close_socket()
    print("Logged out.")


def cmd_cleanup(cfg: dict, _args) -> None:
    """
    Login (which automatically drains up to 20 stale LOGOUT packets the
    gateway may have queued from previous broken sessions), then send a
    clean logout to leave the gateway in a fresh state.
    """
    gw = connect_and_login(cfg)
    print("Session established (stale sessions drained during login).")
    gw.logout()
    gw._close_socket()
    print("Clean logout sent.")


def cmd_position(cfg: dict, _args) -> None:
    pos_port = cfg.get('position_port')
    if not isinstance(pos_port, int):
        # Fall back to impulse_port if position_port is not configured.
        pos_port = port_for_action(cfg, 'impulse')
        print(f"Note: position_port not configured, using impulse_port ({pos_port})")
    gw = connect_and_login(cfg)
    try:
        pos = gw.get_door_position(pos_port)
    finally:
        gw.disconnect()
    if pos < 0:
        print(f"Position: unknown (gateway returned no data for port {pos_port})")
    else:
        print(f"Position: {pos}%")


def cmd_action(cfg: dict, action: str) -> None:
    port = port_for_action(cfg, action)
    gw = connect_and_login(cfg)
    try:
        gw.set_door_state(port)
    finally:
        gw.disconnect()
    print(f"Sent '{action}' on port {port}.")


def cmd_status(cfg: dict, _args) -> None:
    PORT_SCAN_RANGE = 32
    gw = connect_and_login(cfg)
    try:
        print(f"\nFirmware : {gw.get_gw_version()}")

        print(f"\nPorts (scan 0–{PORT_SCAN_RANGE - 1}):")
        found = False
        for pid in range(PORT_SCAN_RANGE):
            name = gw.get_port_name(pid)
            if name is not None:
                label = f"'{name}'" if name else '(no name)'
                print(f"  port {pid}: {label}")
                found = True
        if not found:
            print("  (none found)")

        print("\nUsers:")
        for user in gw.jcmp({'CMD': 'GET_USERS'}):
            admin = ' [admin]' if user.get('isAdmin') else ''
            print(f"  id={user['id']}  name='{user['name']}'{admin}")

        print("\nGroups:")
        groups = gw.jcmp({'CMD': 'GET_GROUPS'})
        if groups:
            print(json.dumps(groups, indent=2))
        else:
            print("  (none)")
    finally:
        gw.disconnect()


def cmd_port(cfg: dict, args) -> None:
    gw = connect_and_login(cfg)
    try:
        gw.set_door_state(args.port_id, args.cmd_value)
    finally:
        gw.disconnect()
    print(f"Sent command 0x{args.cmd_value:02X} to port {args.port_id}.")


# ------------------------------------------------------------------ #
# Entry point
# ------------------------------------------------------------------ #

def main() -> None:
    parser = build_parser()
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format='%(levelname)s %(message)s',
    )

    try:
        cfg = load_config(args.config)
    except FileNotFoundError:
        print(f"Error: config file not found: {args.config}", file=sys.stderr)
        sys.exit(1)

    for required in ('bisecur_ip', 'bisecur_mac', 'bisecur_user', 'bisecur_pw'):
        if not cfg.get(required):
            print(f"Error: '{required}' not set in config.", file=sys.stderr)
            sys.exit(1)

    try:
        if args.command == 'login':
            cmd_login(cfg, args)
        elif args.command == 'logout':
            cmd_logout(cfg, args)
        elif args.command == 'cleanup':
            cmd_cleanup(cfg, args)
        elif args.command == 'position':
            cmd_position(cfg, args)
        elif args.command == 'status':
            cmd_status(cfg, args)
        elif args.command in NAMED_ACTIONS:
            cmd_action(cfg, args.command)
        elif args.command == 'port':
            cmd_port(cfg, args)
    except BisecurError as e:
        print(f"Gateway error: {e}", file=sys.stderr)
        sys.exit(1)
    except ConnectionError as e:
        print(f"Connection error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
