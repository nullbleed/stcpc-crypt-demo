#!/bin/python3
#
# Simple TCP-Chat Server
#
# 2015(c) Bernd Busse, Daniel Jankowski

import socket
import random
from Crypto.Cipher import AES
from Crypto.Cipher import DES

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
    
    # TODO: test encryption
    # TODO: send multiple messages and only listen in background
    data, send = con.recv(4096), " "
    while (mydecrypt(data, key) != "exit" and send != "exit"):
        print("Partner: {0}".format(mydecrypt(data, key)))
        send = input("You: ")
        dsend = myencrypt(send, key)
        con.sendall(dsend)
        if(send != "exit"):
            data = con.recv(4096)
    print("[SERVER] Connection closed!")
    con.close()
    print("[SERVER] Shutting down...")
    sock.close()


def myencrypt(inmsg, key):
    outmsg,i = "".encode("utf-8"), 0
    if((len(inmsg)%16)!=0):
        while ((len(inmsg)%16)!=0):
            inmsg += " "
    print(inmsg)
    while (i != len(inmsg)//16):
        msg = inmsg[i*16:(1+i)*16]
        des1cipher = DES.new(key[:8])
        aescipher = AES.new(key[8:24], AES.MODE_CBC, key[24:40])
        des2cipher = DES.new(key[40:48])
        msg = msg.encode("utf-8")
        c1 = des1cipher.encrypt(msg[:8])
        z = c1 + msg[8:]
        print(len(z))
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
