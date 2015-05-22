#!/bin/python3
#
# Simple TCP-Chat Server
#
# 2015(c) Bernd Busse, Daniel Jankowski

import socket
import random

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def main():
    print("[SERVER] Binding to Adress")
    sock.bind(("0.0.0.0", 1337))
    print("[SERVER] Listening on Port 1337...")
    sock.listen(0)
    con, peer = sock.accept()

    # dhke
    # TODO: primetest
    b = random.randint(2, 2**4096)
    k = random.randint(2, 2**4096)
    n = random.randint(2, 2**4096)
    B = str(sqm(k, b, n))
    print(B)
    con.sendall(str(k).encode("utf-8"))
    con.sendall(str(n).encode("utf-8"))
    con.sendall(B.encode("utf-8"))
    A = con.recv(4096)
    key = str(sqm(int(A.decode("utf-8")), b, n))
    
    # TODO: better encryption than xor or onetimepad(too slow?)
    # TODO: send multiple messages and only listen in background
    data, send = con.recv(4096), ""
    while (sxor(data.decode("utf-8"), key) != "exit" and send != "exit"):
        print("Partner: {0}".format(sxor((data.decode("utf-8")), key)))
        send = input("You: ")
        dsend = sxor(send, key)
        con.sendall(dsend.encode("utf-8"))
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
