#!/usr/bin/python

import socket

sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM)
conn = sock.connect( ("10.0.0.1", 8888))
sock.close()
