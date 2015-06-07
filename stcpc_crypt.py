import random
import time
from Crypto.Cipher import AES
from Crypto.Cipher import DES


def client_dhke(sock):
    a = random.randint(2, 2**4096)
    print("[CLIENT] Negotiate cryptographic parameters")
    k = int(sock.recv(4096).decode("utf-8"))
    print("1...")
    n = int(sock.recv(4096).decode("utf-8"))
    print("2...")
    B = sock.recv(4096)
    print("3...")
    B = B.decode("utf-8")
    A = str(sqm(k, a , n))
    sock.sendall(A.encode("utf-8"))
    key = str(sqm(int(B), a, n))
    key = key.encode("utf-8")
    print("[SUCCESS] Your messages will now be encrypted")
    print("\n==============================================")
    return key


def server_dhke(con):
    print("[SERVER] Negotiating cryptographic parameters")
    b = random.randint(2, 2**4096)
    k = random.randint(2, 2**4096)
    n = random.randint(2, 2**4096)
    B = str(sqm(k, b, n))
    print("1...")
    con.sendall(str(k).encode("utf-8"))
    time.sleep(1)
    print("2...")
    con.sendall(str(n).encode("utf-8"))
    time.sleep(1)
    print("3...")
    con.sendall(B.encode("utf-8"))
    A = con.recv(4096)
    key = str(sqm(int(A.decode("utf-8")), b, n))
    print("[SUCCESS] Encrypting messages")
    print("\n===================================") 
    return key


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
        p1 = des2cipher.decrypt(msg[8:])
        z = msg[:8] + p1
        p2 = aescipher.decrypt(z)
        p3 = des1cipher.decrypt(p2[:8])
        outmsg += (p3 + p2[8:]).decode("utf-8")
        i += 1
    outmsg = outmsg.rstrip('\0')
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
