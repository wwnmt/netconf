#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, unicode_literals, print_function, nested_scopes
import argparse
import datetime
import logging
import os
import platform
import socket
import sys
import time
import datetime
import paramiko as ssh
import threading
import json
from lxml import etree
from netconfd import error, server, util
from netconfd import nsmap_add, NSMAP

nsmap_add("sys", "urn:ietf:params:xml:ns:yang:ietf-system")

stream_dict = {
	'NETCONF':'default NETCONF event stream',
	'SNMP':'SNMP notifications',
	'syslog-critical':'Critical and higher severity'
}
replaySupport_dict = {
	'NETCONF':'true',
	'SNMP':'false',
	'syslog-critical':'true'
}


def date_time_string(dt):
	tz = dt.strftime("%z")
	s = dt.strftime("%Y-%m-%dT%H:%M:%S.%f")
	if tz:
		s += " {}:{}".format(tz[:-2], tz[-2:])
	return s

def stream_add(streams, name, description):
	stream = util.subelm(streams, 'stream')
	stream.append(util.leaf_elm("name", name))
	stream.append(util.leaf_elm("description", description))
	stream.append(util.leaf_elm("replaySupport", replaySupport_dict[name]))

class SSHUserPassController(ssh.ServerInterface):
    """An implementation of paramiko `ServerInterface` that authorizes a single user
    and password.

    :param username: The username to allow.
    :param password: The password to allow.
    """

    def __init__(self, username=None, password=None):
        self.username = username
        self.password = password
        self.event = threading.Event()

    def get_allowed_auths(self, username):
        del username  # unused
        return "password"

    def check_auth_none(self, username):
        del username  # unused
        return ssh.AUTH_FAILED

    def check_auth_password(self, username, password):
        if self.username == username and self.password == password:
            return ssh.AUTH_SUCCESSFUL
        return ssh.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return ssh.OPEN_SUCCEEDED
        return ssh.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_subsystem_request(self, channel, name):
        self.event.set()
        return name == "netconf"

class SystemServer(object):
	def __init__(self, port, host_key, auth, debug):
		self.server = server.NetconfSSHServer(auth, self, port, host_key, debug)

	def close():
		self.server.close()

	def nc_append_capabilities(self, capabilities):
		util.subelm(capabilities,
				"capability").text = "urn:ietf:params:netconf:capability:xpath:1.0"
		util.subelm(capabilities,
				"capability").text = "urn:ietf:params:netconf:capability:notification:1.0"
		util.subelm(capabilities, "capability").text = NSMAP["sys"]

	def rpc_get(self, session, rpc, filter_or_none):
		data = util.elm("nc:data")

		sysc = util.subelm(data, "sys:system-state")
		platc = util.subelm(sysc, "sys:system")

		platc.append(util.leaf_elm("sys:os-name", platform.system()))
		platc.append(util.leaf_elm("sys:os-release", platform.release()))
		platc.append(util.leaf_elm("sys:os-version", platform.version()))
		platc.append(util.leaf_elm("sys:machine", platform.machine()))

		# Clock
		clockc = util.subelm(sysc, "sys:clock")
		now = datetime.datetime.now()
		clockc.append(util.leaf_elm("sys:current-datetime", date_time_string(now)))

		if os.path.exists("/proc/uptime"):
			with open('/proc/uptime', 'r') as f:
				uptime_seconds = float(f.readline().split()[0])
			boottime = time.time() - uptime_seconds
			boottime = datetime.datetime.fromtimestamp(boottime)
			clockc.append(util.leaf_elm("sys:boot-datetime", date_time_string(boottime)))

		# Notification
		attr = { 'xmln':'urn:ietf:params:xml:ns:netmod:notification'}
		netconf = util.subelm(data, "netconf", attr)
		streams = util.subelm(netconf, "streams")
		for k, v in stream_dict.items():
			stream_add(streams, k, v)

		return util.filter_results(rpc, data, filter_or_none, self.server.debug)

	def rpc_get_config(self, session, rpc, source_elm, filter_or_none):  # pylint: disable=W0613
		"""Passed the source element"""
		data = util.elm("nc:data")
		sysc = util.subelm(data, "sys:system")
		sysc.append(util.leaf_elm("sys:hostname", socket.gethostname()))

		# Clock
		clockc = util.subelm(sysc, "sys:clock")
		# tzname = time.tzname[time.localtime().tm_isdst]
		clockc.append(util.leaf_elm("sys:timezone-utc-offset", int(time.timezone / 100)))


		return util.filter_results(rpc, data, filter_or_none)

	def rpc_edit_config(self, session, rpc, *params):
		
		data = util.elm("nc:data")
		data.append(util.leaf_elm("nc:edit-replay", "RPC_OK"))

		return data

	def rpc_copy_config(self, session, rpc, target_elm, source_elm):
		data = util.elm("nc:data")
		data.append(util.leaf_elm("nc:copy-replay", "RPC_OK"))

		return data

	def rpc_delete_config(self, session, rpc, target_elm):
		data = util.elm("nc:data")
		data.append(util.leaf_elm("nc:delete-replay", "RPC_OK"))

		return data

	def rpc_Lock(self, session, rpc, target_elm):
		data = util.elm("nc:data")
		data.append(util.leaf_elm("nc:lock-replay", "RPC_OK"))

		return data

	def rpc_unLock(self, session, rpc, target_elm):
		data = util.elm("nc:data")
		data.append(util.leaf_elm("nc:unlock-replay", "RPC_OK"))

		return data

	def rpc_create_subscription(self, unused_session, rpc, rpc_stream, *unused_params):
		stream = rpc_stream.getchildren()[0].tag.split('}')[1:]
		stream = str(stream[0])
		data = util.elm("nc:data")
		data.append(util.leaf_elm("nc:create-subscription", stream))

		return data

	def rpc_system_restart(self, session, rpc, *params):
		raise error.AccessDeniedAppError(rpc)

	def rpc_system_shutdown(self, session, rpc, *params):
		raise error.AccessDeniedAppError(rpc)


def main(*margs):
	# 解析参数
	parse = argparse.ArgumentParser("Netconf Server")
	parse.add_argument("--username", default="admin", help="netconf username")
	parse.add_argument("--password", default="admin", help="netconf password")
	parse.add_argument("--port", type=int, default=8300, help="server port")
	parse.add_argument("--debug", action="store_true", help="enable debug logging")
	args = parse.parse_args(margs)

	logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)

	host_key = os.path.dirname(__file__) + "server-key"
	auth = SSHUserPassController(username=args.username, password=args.password)
	s = SystemServer(args.port, host_key, auth, args.debug)


	if sys.stdout.isatty():
		print("^C to quit server")
	try:
		while True:
			time.sleep(1)
	except Exception:
		print("quitting server...")

	s.close()


if __name__ == "__main__":
	main()
