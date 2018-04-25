# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, unicode_literals, print_function, nested_scopes

import argparse
import logging
import os
import sys
import getpass
import io
from lxml import etree
from paramiko.pkey import PKey

import netconfd.client as client
from netconfd import NSMAP


def main(*margs):
	parse = argparse.ArgumentParser("Netconf Client")
	parse.add_argument("-H", "--host", default="localhost", help="server host")
	parse.add_argument("-P", "--port", type=int, default=8300, help="server port")
	parse.add_argument("-u", "--username", default="admin", help="input username")
	parse.add_argument("-p", "--password", default="admin", help="input password")
	parse.add_argument("--debug", action="store_true", help="enable debug logging")
	parse.add_argument('--source', default="running", help="Source for get config")
	args = parse.parse_args(margs)

	if args.debug:
		logging.basicConfig(level=logging.DEBUG)
	else:
		logging.basicConfig(level=logging.WARNING)

	session = client.NetconfSSHSession(args.host, args.port, args.username, args.password, debug=args.debug)
	if session == None:
		print('failed connecting netconf ssh server!\n')

	while(1):
		command = raw_input('netconfd>')
		command.lower()
		if not cmp(command, 'hello'):
			result = "\n".join(session.capabilities) + "\n"
		# get
		elif not cmp(command, 'get'):
			select = None
			result = session.get(select)
			result = "  " + etree.tounicode(result, pretty_print=True)
		# get-config
		elif not cmp(command, 'get-config'):
			result = session.get_config(args.source)
			result = "  " + etree.tounicode(result, pretty_print=True)
		# edit-config
		elif not cmp(command, 'edit-config'):
			result = session.edit_config(args.source)
			result = "  " + etree.tounicode(result, pretty_print=True)
		# copy-config
		elif not cmp(command, 'copy-config'):
			result = session.copy_config(args.source, "candidate")
			result = "  " + etree.tounicode(result, pretty_print=True)
		# delete-config
		elif not cmp(command, 'delete-config'):
			result = session.delete_config(args.source)
			result = "  " + etree.tounicode(result, pretty_print=True)	
		# lock		
		elif not cmp(command, 'lock'):
			result = session.Lock(args.source)
			result = "  " + etree.tounicode(result, pretty_print=True)
		# unlock
		elif not cmp(command, 'unlock'):
			result = session.unLock(args.source)
			result = "  " + etree.tounicode(result, pretty_print=True)
		# notification
		## streams
		elif not cmp(command, 'stream'):
			if "urn:ietf:params:netconf:capability:notification:1.0" not in session.capabilities:
				print('not support notification\n')
				continue
			else:
				select = "streams"
				result = session.get(select)
				result = "  " + etree.tounicode(result, pretty_print=True)
		elif (not cmp(command, 'cn')):
			if "urn:ietf:params:netconf:capability:notification:1.0" not in session.capabilities:
				print('not support notification\n')
				continue
			else:
				result = session.create_subscription()
				stream = result.find("nc:create-subscription", NSMAP) 
				#print(stream.text)
				session.stream = stream.text
				result = "  " + etree.tounicode(result, pretty_print=True)
		# exit
		elif not cmp(command, 'exit'):
			result = None
		try:
			if result is not None:
				sys.stdout.write(result)
				command = ''
				result = ''
			else:
				session.close()
				break;
		except UnboundLocalError:
			pass
	print('quit netconfd...')
	
if __name__ == "__main__":
	main()