#!/bin/env python3
# coding: utf-8
#
# Simple TCP-Chat Server
#
# 2015(c) Bernd Busse, Daniel Jankowski

import random
import time
from Crypto.Cipher import AES
from Crypto.Cipher import DES
from Crypto.Util import number
import base64


CLIENT_SAV = 'stcpc_client.crt'
SERVER_SAV = 'stcpc_server.crt'


def client_dhke(sock):
    a = getprime_client()
    k = int(sock.recv(4096).decode("utf-8"))
    n = int(sock.recv(4096).decode("utf-8"))
    B = int(sock.recv(4096).decode("utf-8"))
    A = str(sqm(k, a , n))
    sock.sendall(A.encode("utf-8"))
    key = str(sqm(B, a, n))
    key = key.encode("utf-8")
    return key


def server_dhke(con):
    print("[SERVER] Negotiating cryptographic parameters")
    b,n,k = getprimes_server()
    B = sqm(k, b, n)
    print("1...")
    con.sendall(str(k).encode("utf-8"))
    time.sleep(1)
    print("2...")
    con.sendall(str(n).encode("utf-8"))
    time.sleep(1)
    print("3...")
    con.sendall(str(B).encode("utf-8"))
    A = int(con.recv(4096).decode("utf-8"))
    key = str(sqm(A, b, n))
    print("[SUCCESS] Encrypting messages")
    print("\n===================================") 
    return key


def getprime_client():
    primetest_length = False
    a = 0
    while not primetest_length:
        primetest_length = True
        with open(CLIENT_SAV, 'rb') as f:
            a = f.readline()
        a = int(a.decode('utf-8'))
        if a < 2**4095:
            print('Error! Generating new primes...')
            genprime_client()
            primetest_length = False
    return a


def getprimes_server():
    primetest_length = False
    b,k,n = 0,0,0
    while not primetest_length:
        primetest_length = True
        with open(SERVER_SAV, 'rb') as f:
            for i, line in enumerate(f):
                if i == 0:
                    b = line
                if i == 1:
                    k = line
                if i == 2:
                    n = line
        b,k,n = int(b),int(k),int(n)
        if b < 2**4095 or k < 2**4095 or n > 2**4096:
            print('Error! Generating new primes...')
            genprime_client()
            primetest_length = False
    return b,k,n


def genprime_client():
    a = number.getStrongPrime(4096, 6)
    with open(CLIENT_SAV, 'wb') as f:
        f.write(str(a).encode('utf-8'))
    return True


def genprimes_server():
    b = number.getStrongPrime(4096, 6)
    k = number.getStrongPrime(4096, 6)
    n = number.getStrongPrime(4096, 6)
    with open(SERVER_SAV, 'w') as f:
        f.writelines(str(b) + '\n')
        f.writelines(str(k) + '\n')
        f.writelines(str(n) + '\n')
    return True


def myencrypt(inmsg, key, sector):
    outmsg,i,keypad = "".encode("utf-8"), 0,((sector//16) * 48 % 74)
    inmsg = (base64.b64encode(inmsg.encode("utf-8"))).decode("utf-8")
    if((len(inmsg)%16)!=0):
       while ((len(inmsg)%16)!=0):
           inmsg += "\0"
    while (i != len(inmsg)//16):
        msg = inmsg[i*16:(1+i)*16]
        des1cipher = DES.new(key[(0 + keypad):(8 + keypad)])
        aescipher = AES.new(key[(8 + keypad):(24 + keypad)], AES.MODE_CBC, key[(24 + keypad):(40 + keypad)])
        des2cipher = DES.new(key[(40 + keypad):(48 + keypad)])
        msg = msg.encode("utf-8")
        c1 = des1cipher.encrypt(msg[:8])
        z = c1 + msg[8:]
        c2 = aescipher.encrypt(z)
        c3 = des2cipher.encrypt(c2[8:])
        outmsg += c2[:8] + c3
        i+=1
    return outmsg


def mydecrypt(inmsg, key, sector):
    outmsg,i, keypad = "", 0, ((sector//16) * 48 % 74)
    #print('decrypting...')
    while (i != len(inmsg)//16):
        msg = inmsg[i*16:(i+1)*16]
        des1cipher = DES.new(key[(0 + keypad):(8 + keypad)])
        aescipher = AES.new(key[(8 + keypad):(24 + keypad)], AES.MODE_CBC, key[(24 + keypad):(40 + keypad)])
        des2cipher = DES.new(key[(40 + keypad):(48 + keypad)])
        p1 = des2cipher.decrypt(msg[8:])
        z = msg[:8] + p1
        p2 = aescipher.decrypt(z)
        p3 = des1cipher.decrypt(p2[:8])
        outmsg += (p3 + p2[8:]).decode("utf-8")
        i += 1
    outmsg = (base64.b64decode(outmsg.encode("utf-8"))).decode("utf-8")
    return outmsg


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
