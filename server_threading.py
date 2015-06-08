#!/bin/env python3
#
# TCP Server

import socket as sock
from threading import Thread, Event
import stcpc_crypt as crypt


SERV_ADDR = "0.0.0.0"
SERV_PORT = 1337


class TCPListenServer(Thread):
    def __init__(self, addr_info, max_connections=5):
        super().__init__()
        self.stop_event = Event()
        self.__bind_addr = addr_info
        self.__max_connections = max_connections
        self.__sock = None
        self.__connections = []

    def __log(self, msg):
        print("[SERVER]: {msg}".format(msg=msg))

    def __shutdown(self):
        self.__log("Stopping TCPListenServer")
        for i, client in enumerate(self.__connections):
            client.stop()
            client.join()

        self.__log("Close server socket")
        self.__sock.close()

    def get_event(self):
        return self.stop_event

    def send_all_msg(self, msg):
        for i, client in enumerate(self.__connections):
            client.send_msg(msg)

    def run(self):
        self.__log("Starting TCPListenServer")

        # Listen on TCP Socket
        self.__sock = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
        self.__sock.bind(self.__bind_addr)
        self.__sock.listen(2)
        self.__sock.settimeout(1.0)

        self.__log("listen on {0}:{1}".format(*self.__sock.getsockname()))
        while not self.stop_event.is_set():
            if (not len(self.__connections) > self.__max_connections):
                # Wait for connection Requests
                try:
                    conn = self.__sock.accept()
                    self.__log("Connection from {0}:{1}".format(*conn[1]))
                    self.__key = crypt.server_dhke(conn[0])
                except sock.timeout:
                    continue

                # Add new Coonection Thread
                ct = TCPConnectionThread(conn[0], conn[1], self.__key)
                self.__connections.append(ct)
                ct.start()

            self.stop_event.wait(1.0)

        self.__shutdown()

    def stop(self):
        self.stop_event.set()


class TCPConnectionThread(Thread):
    def __init__(self, socket, peer, key):
        super().__init__()
        self.stop_event = Event()
        self.__peer_info = peer
        self.__sock = socket
        self.__key = key
        self.__sector = 0

    def __log(self, msg):
        print("[{0}:{1}]: {msg}".format(*self.__peer_info, msg=msg))

    def __shutdown(self):
        self.__log("Stopping Connection Thread")

        self.__log("Close client socket")
        self.__sock.close()
        self.__sock = None

    def get_event(self):
        return self.stop_event

    def send_msg(self, msg):
        if self.__sock:
            # Send message
            try:
                self.__sock.setblocking(True)
                emsg = crypt.myencrypt(msg, self.__key, self.__sector)
                self.__sock.sendall(emsg)
                self.__sector = self.__sector + len(emsg)
                self.__sock.settimeout(1.0)
                self.__log("SEND_MSG: {0}".format(msg))
            except sock.timeout:
                return

    def run(self):
        self.__log("Starting Connection Thread")
        self.__sock.settimeout(1.0)

        while not self.stop_event.is_set():
            # Receive some Data
            try:
                data = self.__sock.recv(256)
            except sock.timeout:
                self.stop_event.wait(1.0)
                continue

            if not data:
                self.__log("Received empty message: close connection")
                break
        
            dmsg = crypt.mydecrypt(data, self.__key, self.__sector)
            self.__sector = self.__sector + len(data)
            self.__log("RECV_MSG: {0}".format(dmsg))

        self.__shutdown()

    def stop(self):
        self.stop_event.set()


def main():
    # Start TCPListenServer
    server = TCPListenServer((SERV_ADDR, SERV_PORT))
    server.start()

    # Main Loop Server Control
    while True:
        cmd = input()

        if not server.is_alive():
            break

        if cmd == "exit":
            server.get_event().set()
            break
        elif cmd == "send":
            msg = input("NACHRICHT: ")
            server.send_all_msg(msg)

    return


if __name__ == '__main__':
    main()
