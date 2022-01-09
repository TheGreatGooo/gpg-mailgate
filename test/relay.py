#!/usr/local/bin/python2
#
# This quick-and-dirty script supports only the happy case of SMTP session,
# i.e. what gpg-mailgate/gpg-lacre needs to deliver encrypted email.
#
# It listens on the port given as the only command-line argument and consumes a
# message, then prints it to standard output.  The goal is to be able to
# compare that output with expected clear-text or encrypted message body.
#

import sys
import socket


EXIT_UNAVAILABLE = 1

ENCODING = 'utf-8'

BUFFER_SIZE = 4096
EOM = "\r\n.\r\n"
LAST_LINE = -3


def welcome(msg):
	return b"220 %b\r\n" % (msg)

def ok(msg = b"OK"):
	return b"250 %b\r\n" % (msg)

def bye():
	return b"251 Bye"

def provide_message():
	return b"354 Enter a message, ending it with a '.' on a line by itself\r\n"

def receive_and_confirm(session):
	session.recv(BUFFER_SIZE)
	session.sendall(ok())

def localhost_at(port):
	return ('127.0.0.1', port)

def serve(port):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		s.bind(localhost_at(port))
		s.listen(1)
	except socket.error as e:
		print("Cannot connect", e)
		sys.exit(EXIT_UNAVAILABLE)

	(conn, addr) = s.accept()
	conn.sendall(welcome(b"TEST SERVER"))

	receive_and_confirm(conn)				# Ignore HELO/EHLO
	receive_and_confirm(conn)				# Ignore sender address
	receive_and_confirm(conn)				# Ignore recipient address

	data = conn.recv(BUFFER_SIZE)
	conn.sendall(provide_message())

	# Consume until we get <CR><LF>.<CR><LF>, the end-of-message marker.
	message = ''
	while not message.endswith(EOM):
		message += conn.recv(BUFFER_SIZE).decode(ENCODING)
	conn.sendall(ok(b"OK, id=test"))

	conn.recv(BUFFER_SIZE)
	conn.sendall(bye())

	conn.close()

	# Trim EOM marker as we're only interested in the message body.
	return message[:-len(EOM)]

def error(msg, exit_code):
	print("ERROR: %s" % (msg))
	sys.exit(exit_code)


if len(sys.argv) < 2:
	error("Usage: relay.py PORT_NUMBER", EXIT_UNAVAILABLE)

port = int(sys.argv[1])
body = serve(port)

print(body)
