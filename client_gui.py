#!/bin/env python3
# coding: utf-8
#
# Simple TCP-Chat Client                                                                                                                                           
#
# 2015(c) Bernd Busse, Daniel Jankowski

import urwid
import socket as sock
from threading import Thread, Event
import urwid
import stcpc_crypt as crypt
import time


PROGNAME = 'stcpc - crypt demo(beta 0.3)' 
HASKEY = False

class ClientSock(Thread):
    
    def __init__(self, addr, port):
        super().__init__()
        self.stop_event = Event()
        self.__server = (addr, port)
        self.sock = None
        self.__callback = None

    def __log(self, msg):
        self.__callback.handle_logging("STATUS: {0}".format(msg))

    def __shutdown(self):
        self.__sock.close()

    def get_event(self):
        return self.stop_event

    def set_callback(self, callback):
        if callback:
            self.__callback = callback

    def negotiate_key(self):
        self.__key = crypt.client_dhke(self.__sock)
        self.__log("Success! Your messages are now encrypted")
        return self.__key
    
    def set_haskey(self):
        global HASKEY
        HASKEY = True

    def get_sock(self):
        return self.__sock

    def send_msg(self, msg, key):
        emsg = crypt.myencrypt(msg, key, 0)
        try:
            self.__sock.sendall(emsg)
        except Exception as e:
            self.__log("Cannot send message: {0}".format(e))

    def run(self):
        self.__sock = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
        try:
            self.__log("Connecting to {0}:{1}...".format(*self.__server))
            self.__sock.settimeout(10.0)
            self.__sock.connect(self.__server)
            self.__sock.settimeout(4.0)
            self.__log("Connected")
        except Exception as e:
            self.__log("Cannot connect to {0}:{1}".format(*self.__server))
            self.__shutdown()
        while not self.stop_event.is_set():
            if HASKEY:
                try:
                    data = self.__sock.recv(256)
                except sock.timeout:
                    self.stop_event.wait(1.0)
                    continue
                if not data:
                    self.__log("Received empty message. Closing connection...")
                    break
                msg = crypt.mydecrypt(data, self.__key, 0)
                self.__log(msg)
                self.__callback.handle_incoming_message(msg)
        self.__shutdown()


class MainLayout(urwid.Frame):
    palette = [
        ('normal', 'white', 'black'),
        ('error', 'red', 'black'),
        ('warning', 'yellow', 'black')
            ]
    
    def __init__(self):
        self.__walker = urwid.SimpleListWalker([])
        self.__list = urwid.ListBox(self.__walker)
        self.__input = urwid.Edit(caption="$ ")

        list_cont = urwid.LineBox(self.__list, title=PROGNAME)
        input_cont = urwid.LineBox(self.__input)

        super().__init__(list_cont, footer=input_cont, focus_part='footer')

        self.__connection = None
        self.__last_command_failed = False

        self.__walker.append(urwid.Text("          __", urwid.LEFT))
        self.__walker.append(urwid.Text("         /\\ \\__                          ", urwid.LEFT))
        self.__walker.append(urwid.Text("     ____\\ \\ ,_\\   ___   _____     ___", urwid.LEFT))
        self.__walker.append(urwid.Text("    /',__\\\\ \\ \\/  /'___\\/\\ '__`\\  /'___\\ ", urwid.LEFT))
        self.__walker.append(urwid.Text("   /\\__, `\\\\ \\ \\_/\\ \\__/\\ \\ \\L\\ \\/\\ \\__/ ", urwid.LEFT))
        self.__walker.append(urwid.Text("   \\/\\____/ \\ \\__\\ \\____\\\\ \\ ,__/\\ \\____\\", urwid.LEFT))
        self.__walker.append(urwid.Text("    \\/___/   \\/__/\\/____/ \\ \\ \\/  \\/____/", urwid.LEFT))
        self.__walker.append(urwid.Text("                           \\ \\_\\", urwid.LEFT))
        self.__walker.append(urwid.Text("                            \\/_/       (beta 0.3 - crypt demo)", urwid.LEFT))
        self.__walker.append(urwid.Text("", urwid.CENTER))

    def __shutdown(self):
        raise urwid.ExitMainLoop()

    def __parse_input(self):
        inp = self.__input.get_edit_text()
        
        self.__input.set_edit_text("")

        # commands
        if inp.startswith('/'):
            if inp.strip() == '/exit':
                self.__shutdown()
            elif inp.startswith('/connect'):
                ar = inp.split(' ')
                if not len(ar) == 3:
                    self.__walker.append(urwid.Text(('error', u"Not enough args"), urwid.CENTER))
                    return
                else:
                    self.connect(ar[1], int(ar[2]))
                    time.sleep(1)
                    return
            elif inp.strip() == '/disconnect':
                self.disconnect()
                return

        self.__send_msg(inp)

    def __send_msg(self, msg):
        if self.__connection:
            self.__connection.send_msg(msg, self.__key)
            self.__walker.append(urwid.Text(msg, urwid.RIGHT))

    def handle_logging(self, msg):
        self.__walker.append(urwid.Text(msg, urwid.CENTER))

    def handle_incoming_message(self, msg):
        self.__walker.append(urwid.Text(msg, urwid.LEFT))

    def connect(self, addr, port):
        if not self.__connection:
            # Connect to server
            self.__connection = ClientSock(addr, port)
            self.__connection.set_callback(self)
            self.__connection.start()
            time.sleep(1)
            self.__key = self.__connection.negotiate_key() 
            self.__connection.set_haskey()

    def disconnect(self):
        if self.__connection is not None:
            self.__connection.get_event().set()
            self.__connection.join()
            self.__connection = None

    def keypress(self, size, key):
        if key == 'enter':
            self.__parse_input()
            return
        elif key == 'esc':
            self.__shutdown()

        return super().keypress(size, key)



def main():
    main_layout = MainLayout()

    loop = urwid.MainLoop(main_layout, screen=urwid.raw_display.Screen())
    loop.run()


if __name__ == '__main__':
    main()
