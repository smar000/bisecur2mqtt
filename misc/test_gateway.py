#!/usr/bin/env python3
"""
Quick smoke-test: connect, login, then query firmware version, ports, users, and groups.
Reads config from bisecur2mqtt.conf (or $BISECUR2MQTT_CONFIG).
"""

import ast
import json
import logging
import os
import sys

from bisecur_client import BisecurGateway

logging.basicConfig(level=logging.DEBUG, format='%(levelname)s %(message)s')

CONFIG_FILE = os.getenv('BISECUR2MQTT_CONFIG', 'bisecur2mqtt.conf')
PORT_SCAN_RANGE = 32  # scan port IDs 0..31; raise if your setup has more

def load_config(path):
    cfg = {}
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

try:
    cfg = load_config(CONFIG_FILE)
except FileNotFoundError:
    print(f"Config file not found: {CONFIG_FILE}", file=sys.stderr)
    sys.exit(1)

gw = BisecurGateway(
    ip      = cfg['bisecur_ip'],
    gw_mac  = cfg['bisecur_mac'],
    src_mac = cfg.get('src_mac', '000000000006'),
)

print(f"\nConnecting to {cfg['bisecur_ip']} ...")
gw.connect()

print(f"Logging in as '{cfg['bisecur_user']}' ...")
gw.login(cfg['bisecur_user'], cfg['bisecur_pw'])

print("\n--- (a) Firmware version ---")
print(gw.get_gw_version())

print(f"\n--- (b) Ports (GET_PORT_NAME scan 0..{PORT_SCAN_RANGE - 1}) ---")
for pid in range(PORT_SCAN_RANGE):
    name = gw.get_port_name(pid)
    if name is not None:
        print(f"  port {pid}: '{name}'")

print("\n--- (c) Users (GET_USERS) ---")
print(json.dumps(gw.jcmp({'CMD': 'GET_USERS'}), indent=2))

print("\n--- (d) Groups (GET_GROUPS) ---")
print(json.dumps(gw.jcmp({'CMD': 'GET_GROUPS'}), indent=2))

gw.disconnect()
print("\nDone.")
