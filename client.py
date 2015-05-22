#!/bin/python3
#
# Simple TCP-Chat Client                                                                                                                                           
#
# 2015(c) Bernd Busse, Daniel Jankowski

import socket
import random
from Crypto.Cipher import AES
from Crypto.Cipher import DES

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
    key = key.encode("utf-8")
    
    # TODO: test encryption
    # TODO: send multiple messages and only listen in background
    i,data = 0,"no"
    while (i != "exit" and data != "exit"):
        i = input("You: ")
        send = myencrypt(i, key)
        sock.sendall(send)
        if(i != "exit"):
            data = sock.recv(256)
            data = mydecrypt(data, key)
            print ("Partner: " + data)
    print("[CLIENT] Connection closed! Exiting...")


def myencrypt(inmsg, key):
    outmsg,i = "".encode("utf-8"), 0
    if((len(inmsg)%16)!=0):
        while ((len(inmsg)%16)!=0):
            inmsg += "\0"
    while (i != len(inmsg)//16):
        msg = inmsg[i*16:(1+i)*16]
        des1cipher = DES.new(key[:8])
        aescipher = AES.new(key[8:24], AES.MODE_CBC, key[24:40])
        des2cipher = DES.new(key[40:48])
        msg = msg.encode("utf-8")
        c1 = des1cipher.encrypt(msg[:8])
        z = c1 + msg[8:]
        c2 = aescipher.encrypt(z)
        c3 = des2cipher.encrypt(c2[8:])
        outmsg += c2[:8] + c3
        i+=1
    return outmsg


def mydecrypt(inmsg, key):
    outmsg,i = "", 0
    while (i != len(inmsg)//16):
        msg = inmsg[i*16:(i+1)*16]
        des1cipher = DES.new(key[:8])
        aescipher = AES.new(key[8:24], AES.MODE_CBC, key[24:40])
        des2cipher = DES.new(key[40:48])
        #msg = msg.encode("utf-8")
        p1 = des2cipher.decrypt(msg[8:])
        z = msg[:8] + p1
        p2 = aescipher.decrypt(z)
        p3 = des1cipher.decrypt(p2[:8])
        outmsg += (p3 + p2[8:]).decode("utf-8")
        i += 1
    outmsg = outmsg.rstrip('\0')
    return outmsg


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
