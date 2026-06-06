#!/usr/bin/python
##############################################################################
# Copyright (c) 2024 Microsoft Corporation
# Copyright (c) 2026 Eclipse ThreadX contributors
#
# This program and the accompanying materials are made available under the
# terms of the MIT License which is available at
# https://opensource.org/licenses/MIT.
#
# SPDX-License-Identifier: MIT
##############################################################################


import socket

sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM)
conn = sock.connect( ("10.0.0.1", 8888))
sock.close()
