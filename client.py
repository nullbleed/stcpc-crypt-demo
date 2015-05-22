#!/bin/python3
#
# Simple TCP-Chat Client                                                                                                                                           
#
# 2015(c) Bernd Busse, Daniel Jankowski

import socket
import random

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def main():
    # addr = input("Bitte die Adresse eingeben: ")
    # hardcoded node for testing
    print("[CLIENT] Connecting to server...")
    #addr = "10.196.229.33"
    # localhost for testing
    addr = "127.0.0.1"
    sock.connect((addr, 1337))
    print("[SUCCESS] connected!")
    
    # dhke
    # TODO: primetest
    a = random.randint(2, 2**4096)
    k = int(sock.recv(4096).decode("utf-8"))
    n = int(sock.recv(4096).decode("utf-8"))
    B = sock.recv(4096)
    B = B.decode("utf-8")
    print(B)
    A = str(sqm(k, a , n))
    sock.sendall(A.encode("utf-8"))
    key = str(sqm(int(B), a, n))
    
    # TODO: better encryption than xor or onetimepad(too slow?)
    # TODO: send multiple messages and only listen in background
    i,data = 0,0
    while (i != "exit" and data != "exit"):
        i = input("You: ")
        send = sxor(i, key)
        send = send.encode("utf-8")
        sock.sendall(send)
        if(i != "exit"):
            data = sock.recv(256)
            print ("Partner: {0}".format(sxor((data.decode("utf-8")), key)))
    print("[CLIENT] Connection closed! Exiting...")


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
