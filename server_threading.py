#!/bin/env python3
# coding: utf-8
#
# Simple TCP-Chat Server
#
# 2015(c) Bernd Busse, Daniel Jankowski

import socket as sock
from threading import Thread,Event

SERV_ADDR = "0.0.0.0"
SERV_PORT = "1337"

class ServerSock(Thread):
    def __init__(self, addr_info, max_connections=5):
        super.__init__()


def main():
    server = None


if __name__ == '__main__':
    main()
