import os
import sys
import subprocess
import logging as log
import paho.mqtt.client as paho   # pip install paho-mqtt
import time
from datetime import datetime
import socket
import string
import json, ast
import traceback

import threading

from pysecur3.client import MCPClient
from pysecur3.MCP import MCPGenericCommand

VERSION= "0.7"
DEBUG=False


CONFIG=os.getenv('MQTT2BISECUR_CONFIG', 'mqtt2bisecur.conf')

class Config(object):
	def __init__(self, filename=CONFIG):
		self.config = {}
		exec(compile(open(filename, "rb").read(), filename, 'exec'), self.config)

	def get(self, key, default=None):
		return self.config.get(key, default)

try:
	cf = Config()
except Exception as e:
	print("Cannot load configuration from file {}: {}".format(CONFIG, str(e)))
	sys.exit(2)


MQTT_TOPIC_BASE = cf.get("mqtt_topic_base", "bisecur2mqtt")
MQTT_COMMAND_SUBTOPIC = "send_command"
MQTT_QOS=0

MQTT_CLIENT_SUB = None
MQTT_CLIENT_PUB = None

CLI = None
LAST_DOOR_STATE = None
POS_TRACKING_THREAD = None
DO_EXIT_THREAD = False

MAX_RETRIES = 2

CMD_GET_TYPE = 49
CMD_GET_STATE = 50
CMD_SET_STATE = 51

LOGFILE = cf.get('logfile', 'bisecur2mqtt.log')
#LOGFORMAT = '%(asctime)-15s %(funcName).10s %(message)s'
LOGFORMAT = "%(asctime)10s [%(filename)s:%(lineno)3s]  %(message)s [%(funcName)s()]"

if DEBUG:
	log.basicConfig(filename=LOGFILE, level=log.DEBUG, format=LOGFORMAT)
else:
	log.basicConfig(filename=LOGFILE, level=log.INFO, format=LOGFORMAT)

stderrLogger=log.StreamHandler()
stderrLogger.setFormatter(log.Formatter(LOGFORMAT))
log.getLogger().addHandler(stderrLogger)


log.info("Starting")
log.debug("DEBUG MODE")


def do_command(cmd):
	cmd = cmd.lower().strip()
	publish_to_mqtt(f"{MQTT_COMMAND_SUBTOPIC}/command", datetime.now().strftime("%Y-%m-%dT%H:%M:%S"), ts_only=True)

	# Generic Commands:
	# 	GET_TYPE = 49, GET_STATE = 50, SET_STATE = 51
	# Port Types:   IMPULS(1), UP(4), DOWN(5), HALF(6), LIGHT(8),
	
	resp = None	
	try:
		if cmd in "get_door_state get_door_position" :
			resp, _, _ = get_door_status()

		elif cmd in "up down open close stop impulse partial light":
			cmd = cmd.replace("open", "up").replace("close", "down")
			resp = do_door_action(cmd)

		elif cmd == "get_ports":
			resp = get_ports()

		elif cmd in "get_version get_gw_version":
			resp = get_gw_version()
			
		elif cmd == "login":
			resp = do_gw_login()

		elif cmd in "sys_restart init_bisecur_gw":
			resp = init_bisecur_gw(True)

		else:
			resp = (f"Command '{cmd} is not recognised")

		check_mcp_error(resp)	
		publish_to_mqtt(f"{MQTT_COMMAND_SUBTOPIC}/response", resp)
		
	except Exception as ex:
		log.error(ex)
		traceback.print_exc()
		check_mcp_error(resp)
	return	

def publish_to_mqtt(topic, payload, topic_base=MQTT_TOPIC_BASE, qos=MQTT_QOS, retain=False, ts_only=False):
	if MQTT_CLIENT_SUB:
		if not isinstance(payload, str):
			payload = str(payload)
		try:
			if not ts_only:
				log.debug(f"---> MQTT pub: {topic_base}/{topic} {payload}")
				MQTT_CLIENT_SUB.publish(f"{topic_base}/{topic}", payload, qos=qos, retain=retain)
			
			log.debug(f"---> MQTT pub: {topic_base}/{topic}_ts {datetime.now().strftime('%Y-%m-%dT%H:%M:%S')}")
			MQTT_CLIENT_SUB.publish(f"{topic_base}/{topic}_ts", datetime.now().strftime("%Y-%m-%dT%H:%M:%S"), qos=qos, retain=retain)
		except Exception as ex:
			log.error(f"Error in topic: {topic}, payload: {payload}")
			log.error(ex)

	else:
		log.warning(f"Ignoring publish to broker as 'MQTT_CLIENT_PUB' not initalised ({topic} {payload})")
	

def get_gw_version():
	try:
		resp = CLI.get_gw_version()	
		version = resp.payload.command.gw_version
		log.info(f"Gateway HW Version: {version}")
		publish_to_mqtt("attributes/gw_hw_version", version)
		return resp, version

	except Exception as ex:
		log.error(ex)
		traceback.print_exc()


def get_ports():
	cmd_mcp = {"CMD":"GET_GROUPS", "FORUSER":0}
	try:
		resp = CLI.jcmp(cmd_mcp)
		ports = resp.payload.payload
		ports = ast.literal_eval(ports.decode("utf-8")) # convert from binary

		log.info(f"Ports for user 0: {json.dumps(ports, indent=4, sort_keys=True)}")
		publish_to_mqtt("attributes/user0_ports", json.dumps(ports))

		return resp, ports
	except Exception as ex:
		log.error(ex)
		traceback.print_exc()


def get_door_status():
	retries = 0
	while retries < MAX_RETRIES:
		try:
			resp = CLI.get_transition(impulse_port) 
			#if resp.payload.command.error_code.value == 10: # PORT_ERROR
				
			state = None
			if resp and resp.payload and hasattr(resp.payload.command , "percent_open"):
				position = resp.payload.command.percent_open 
				if position == 0:
					state = "closed"
					log.info("Garage door is CLOSED")
				elif position == 100:
					state = "open"
					log.info("Garage door is OPEN")
				else:
					log.info(f"Garage door is {resp.payload.command.percent_open}% OPEN")
			else:
				position = -1
				log.warning(f"get_transition response has no 'percentage_open' attribute (resp: {resp})")
			
			# log.info(f"posting position {position} and state {state} to MQTT....")
			publish_to_mqtt("garage_door/position", position)
			publish_to_mqtt("garage_door/state", state)

			return resp, position, state
		except Exception as ex:
			log.error(ex)
			if DEBUG:
				traceback.print_exc()
			if CLI.last_error:
				log.error(f"----------- CLI error found {CLI.last_error}") #TODO!!!
				time.sleep(.5)
				retries += 1
			else:
				break
			

def track_realtime_door_position(current_pos=None, last_action=None):
	publish_to_mqtt("garage_door/position", current_pos)
					
	global LAST_DOOR_STATE
	global DO_EXIT_THREAD 

	state = ""
	last_pos = None

	DO_EXIT_THREAD = False

	while not DO_EXIT_THREAD and ((state != "open" and last_action == "up open") or (state != "closed" and last_action in "down close") or current_pos != last_pos):
		time.sleep(1)
		last_pos = current_pos
		resp, current_pos, state = get_door_status()
		if not check_mcp_error(resp):
			if current_pos < last_pos:
				state = "closing"
			elif current_pos > last_pos:
				state = "opening"
			LAST_DOOR_STATE = state
			publish_to_mqtt("garage_door/position", current_pos)
			publish_to_mqtt("garage_door/state", state)	
	LAST_DOOR_STATE = state
	return LAST_DOOR_STATE


def do_door_action(action):	
	global LAST_DOOR_STATE
	if action == "stop":
		# Do reverse action to stop current direction
		if LAST_DOOR_STATE == "opening":
			action = "down"
		elif LAST_DOOR_STATE == "closing":
			action = "up"
		else:
			log_msg = f"Ignoring 'stop' command as current door movement direction unknown (LAST_DOOR_STATE is '{LAST_DOOR_STATE}')"
			log.warning(log_msg)
			return log_msg

	if (action in "impulse up down partial light" and f"{action}_port" in globals()) or action == "stop":		
		port = globals()[f"{action}_port"]		
		value = port << 8 | 0xFF
		mcp_cmd = MCPGenericCommand.construct(CMD_SET_STATE, value)
		action_resp = CLI.generic(mcp_cmd, False)

		if not check_mcp_error(action_resp):
			current_pos = action_resp.payload.command.percent_open
			# publish_to_mqtt("garage_door/response", str(action_resp.payload.command))
			
			global POS_TRACKING_THREAD
			if POS_TRACKING_THREAD and POS_TRACKING_THREAD.is_alive():				
				global DO_EXIT_THREAD
				DO_EXIT_THREAD = True
				time.sleep(0.1)
				counter = 0
				log.debug(f"...Active thread count: {threading.activeCount()} ")
				while POS_TRACKING_THREAD.is_alive() and counter < 15:					
					log.debug(f"\t----> WAITING .... POS_TRACKING_THREAD.is_alive: {POS_TRACKING_THREAD.is_alive()}")
					time.sleep(.5)
					counter += 0.5
			if POS_TRACKING_THREAD: log.debug(f"----> POS_TRACKING_THREAD.is_alive: {POS_TRACKING_THREAD.is_alive()}")
			
			POS_TRACKING_THREAD = threading.Thread(name='pos_tracking_thread', target=track_realtime_door_position, args=(current_pos, action,))
			POS_TRACKING_THREAD.start()
			log.debug(f"New thread spawned for 'do_command': {POS_TRACKING_THREAD}")
		

			# track_realtime_door_position(current_pos, action)

		return action_resp

	else:
		log.error(f"Port '{action}_port' is not defined in")
		return None

def do_gw_login():
	bisecur_user = cf.get("bisecur_user")
	bisecur_pw = cf.get("bisecur_pw")
	
	log.debug(f"Logging in to Bisecur Gateway as user '{bisecur_user}'")		
	CLI.login(bisecur_user, bisecur_pw)
	if CLI.token:
		log.info(f"User '{bisecur_user}' logged in to Bisecur Gateway with token '{CLI.token}'")	
		return CLI.token
	else:
		log.warning(f"Bisecur Gateway login failed for user '{bisecur_user}'. Exiting...")	
		return None


def check_mcp_error(resp):
	if CLI.last_error: #TODO!!! Tidy up...
		log.error(f"--- 1. CLI.last_error: {CLI.last_error}")
		error_obj = {"error_code": resp.payload.command.error_code.value, "error": resp.payload.command.error_code.name}
		publish_to_mqtt(f"{MQTT_COMMAND_SUBTOPIC}/error", json.dumps(error_obj))

	elif resp and hasattr(resp, "resp.payload") and hasattr(resp, "resp.payload.command_id") and resp.payload.command_id == 1 and resp.payload.command.error_code:
		log.error(f"MCP error '{resp.payload.command.error_code.value}' occurred (code: {resp.payload.command.error_code.name}) ")
		# Error 12 is Permission Denied
		# CLI.last_error = resp.payload.command.error_code
		log.error(f"--- 2. CLI.last_error: {CLI.last_error}")
		error_obj = {"error_code": resp.payload.command.error_code.value, "error": resp.payload.command.error_code.name}
		publish_to_mqtt(f"{MQTT_COMMAND_SUBTOPIC}/error", json.dumps(error_obj))
		return error_obj
	
	else:
		# CLI.last_error = None
		return None

def on_message(mosq, userdata, msg):
	log.info(f"---> Topic '{msg.topic}' received command '{msg.payload.decode('utf-8')}'")
	cmd = msg.payload.decode('utf-8')
	do_command(cmd)


def on_connect(mosq, userdata, flags, result_code):	
	sub_topic = f"{MQTT_TOPIC_BASE}/{MQTT_COMMAND_SUBTOPIC}/command"
	log.info(f"Connected to MQTT broker. Subscribing to '{sub_topic}'")
	MQTT_CLIENT_SUB.subscribe(sub_topic, MQTT_QOS)
	publish_to_mqtt("state", "online")
	init_ha_discovery()
	

def on_disconnect(mosq, userdata, rc):
	publish_to_mqtt("state", "offline")
	log.info("MQTT session disconnected")
	time.sleep(10)


def init_ha_discovery():
	payload = {"door_commands_list":["impulse","up","down","partial","stop","light"],"json_attributes_topic":f"{MQTT_TOPIC_BASE}/attributes","name":"Bisecur Gateway: Garage Door","schema":"state","supported_features":["impulse","up","down","partial","stop","light","get_door_state","get_ports","login","sys_reset"],"availability_topic":f"{MQTT_TOPIC_BASE}/state","payload_available":"online","payload_not_available":"offline","unique_id":"bs_garage_door","device_class":"garage","payload_close":"down","payload_open":"up","payload_stop":"impulse","position_open":100.0,"position_closed":0.0,"position_topic":f"{MQTT_TOPIC_BASE}/garage_door/position","state_topic":f"{MQTT_TOPIC_BASE}/garage_door/state","command_topic":f"{MQTT_TOPIC_BASE}/{MQTT_COMMAND_SUBTOPIC}/command"}
	bisecur_mac = cf.get("bisecur_mac", "").replace(':','')	
	bisecur_ip = cf.get("bisecur_ip", None)
	payload["connections"] = ["mac", bisecur_mac, "ip", bisecur_ip]
	payload["sw_version"] = VERSION
	_, payload["gw_hw_version"] = get_gw_version()
	
	mqtt_topic_HA_discovery = cf.get("mqtt_topic_HA_discovery", "homeassistant")
	publish_to_mqtt("cover/bisecur/config", json.dumps(payload), f"{mqtt_topic_HA_discovery}" )
	publish_to_mqtt("attributes/system_version", VERSION )
	publish_to_mqtt("attributes/gw_ip_address", bisecur_ip)
	publish_to_mqtt("attributes/gw_mac_address", bisecur_mac)


def init_bisecur_gw(is_restart=False):
	global CLI
	if is_restart and CLI and not hasattr(CLI, "last_error"):
		CLI.logout()

	# Init Bisecur Gateway stuff
	src_mac = cf.get("src_mac", "FF:FF:FF:FF:FF:FF").replace(':','')
	bisecur_mac = cf.get("bisecur_mac", "").replace(':','')	
	bisecur_ip = cf.get("bisecur_ip", None)
	if not (bisecur_ip and bisecur_mac):
		log.error("bisecur Gateway IP and MAC addresses must be specified in the config file")
		sys.exit(2)

	log.debug(f"Gateway IP: {bisecur_ip}, bisecur_mac: {bisecur_mac}, src_mac: {src_mac}")

	CLI = MCPClient(bisecur_ip, 4000, bytes.fromhex(src_mac), bytes.fromhex(bisecur_mac))

	login_token = do_gw_login()
	if not login_token:
		sys.exit(2)
	
	return login_token


if __name__ == '__main__':
	# Init mqtt
	userdata = {
	}

	clientid = cf.get('mqtt_client_id', 'biscure2mqtt-{}'.format(os.getpid()))
	# initialise MQTT broker connection. Use separate clients for sub and pub, as loop_start/forever are blocking
	MQTT_CLIENT_SUB = paho.Client(f"{clientid}_sub", clean_session=False)
	MQTT_CLIENT_PUB = paho.Client(f"{clientid}_pub", clean_session=False)


	MQTT_CLIENT_SUB.will_set(f"{MQTT_TOPIC_BASE}/state","offline", qos=0)

	MQTT_CLIENT_SUB.on_message = on_message
	MQTT_CLIENT_SUB.on_connect = on_connect
	MQTT_CLIENT_SUB.on_disconnect = on_disconnect


	# Delays will be: 3, 6, 12, 24, 30, 30, ...
	#MQTT_CLIENT_SUB.reconnect_delay_set(delay=3, delay_max=30, exponential_backoff=True)

	if cf.get('mqtt_username') is not None:
		MQTT_CLIENT_SUB.username_pw_set(cf.get('mqtt_username'), cf.get('mqtt_password'))
		MQTT_CLIENT_PUB.username_pw_set(cf.get('mqtt_username'), cf.get('mqtt_password'))

	if cf.get('mqtt_tls') is not None:
		MQTT_CLIENT_SUB.tls_set()

	MQTT_CLIENT_SUB.connect(cf.get('mqtt_broker', 'localhost'), int(cf.get('mqtt_port', '1883')), 60)
	MQTT_CLIENT_PUB.connect(cf.get('mqtt_broker', 'localhost'), int(cf.get('mqtt_port', '1883')), 60)
	log.info("Connecting to MQTT broker")

	# Init Bisecur Gateway 
	init_bisecur_gw()

	if DEBUG:
		log.debug("Getting bisecur Gateway 'groups' for user 0...")
		cmd = {"CMD":"GET_GROUPS", "FORUSER":0}
		CLI.jcmp(cmd)

	impulse_port    = cf.get("impulse_port", None)
	up_port         = cf.get("up_port", None)
	down_port       = cf.get("down_port", None)
	partial_port    = cf.get("partial_port", None)
	light_port      = cf.get("light_port", None)
	
	if impulse_port is None or not isinstance(impulse_port, int):
		log.error("'Impulse' port number not found in configuration file")
		sys.exit(2)

	get_door_status()


	while True:
		try:
			MQTT_CLIENT_SUB.loop_forever()
		except socket.error:
			print("... doing sleep(5)")
			time.sleep(5)
		except KeyboardInterrupt:
			log.info("Shutting down connections")
		finally:		
			log.info("Changing MQTT state to 'offline'")
			MQTT_CLIENT_PUB.publish(f"{MQTT_TOPIC_BASE}/state", "offline")
			MQTT_CLIENT_SUB.loop_stop()
			if CLI:
				if hasattr(CLI, "last_error") and CLI.last_error is not None and CLI.last_error.value == 12: 
					#Permission denined error (12) seems to make the system hang on receive
					log.info(f"Logging out of Bisecur Gateway ({CLI.token})")
					CLI.logout()	
				elif hasattr(CLI, "last_error"):
					log.debug(f"Pre-logout: Biscure last error: ({CLI.last_error})")							
			
			log.info(f"Active threads: {threading.activeCount()}")
			log.debug("Tidying up spawned threads...")
			main_thread = threading.currentThread()
			for t in threading.enumerate():
				if t is main_thread:
					log.info(f"... ignoring main_thread '{main_thread.getName()}'")
					continue
				log.info(f"...joining spawned thread '{t.getName()}'")
				t.join()

			log.info("Done!")
			sys.exit(0)

