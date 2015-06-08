#!/bin/python3
# coding: utf-8
#
# Simple TCP-Chat Server
#
# 2015(c) Bernd Busse, Daniel Jankowski

import socket
import random
import time
from Crypto.Cipher import AES
from Crypto.Cipher import DES
import stcpc_crypt as crypt

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def main():
    print("[SERVER] Binding to Adress")
    sock.bind(("0.0.0.0", 1337))
    print("[SERVER] Listening on Port 1337...")
    sock.listen(0)
    con, peer = sock.accept()

    # dhke
    # TODO: primetest
    key = crypt.server_dhke(con)    

    # TODO: test encryption
    data, send, sector= con.recv(4096), " ",0
    while (crypt.mydecrypt(data, key, sector) != "exit" and send != "exit"):
        print("Partner: {0}".format(crypt.mydecrypt(data, key, sector)))
        sector += len(data)
        send = input("You: ")
        dsend = crypt.myencrypt(send, key, sector)
        con.sendall(dsend)
        sector += len(dsend)
        if(send != "exit"):
            data = con.recv(4096)
    print("[SERVER] Connection closed!")
    con.close()
    print("[SERVER] Shutting down...")
    sock.close()


def sxor(s1, s2):
    return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(s1, s2))


def sqm(a, e, m):
    bitlen = len(bin(e)[2:])
    c = a                                                                                                                                                            
    bitlen -= 1

    while bitlen > 0:
        bitlen -= 1
        c = (c * c) % m
        mul = ((e >> bitlen) & 0x1)
        if mul:
            c = (c * a) % m
    return c


if __name__ == '__main__':
    main()
