#!/bin/python3
# coding: utf-8
#
# Simple TCP-Chat Client                                                                                                                                           
#
# 2015(c) Bernd Busse, Daniel Jankowski

import socket
import random
import time
from Crypto.Cipher import AES
from Crypto.Cipher import DES
import stcpc_crypt as crypt

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def logo():
    print("       __")
    print("      /\\ \\__                          ")
    print("  ____\\ \\ ,_\\   ___   _____     ___")
    print(" /',__\\\\ \\ \\/  /'___\\/\\ '__`\\  /'___\\ ")
    print("/\\__, `\\\\ \\ \\_/\\ \\__/\\ \\ \\L\\ \\/\\ \\__/ ")
    print("\\/\\____/ \\ \\__\\ \\____\\\\ \\ ,__/\\ \\____\\")
    print(" \\/___/   \\/__/\\/____/ \\ \\ \\/  \\/____/")
    print("                        \\ \\_\\")
    print("                         \\/_/       (beta 0.1 - crypt demo)")
    print("")

def main():
    logo()
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
    key = crypt.client_dhke(sock)

    # TODO: test encryption
    i,ddata,sector = 0,"no",0
    while (i != "exit" and ddata != "exit"):
        i = input("You: ")
        send = crypt.myencrypt(i, key, sector)
        sock.sendall(send)
        sector += len(send)
        if(i != "exit"):
            data = sock.recv(256)
            ddata = crypt.mydecrypt(data, key, sector)
            sector += len(data)
            print ("Partner: " + ddata)
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
