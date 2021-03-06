#!/bin/env python3
# coding: utf-8
#
# Simple TCP-Chat Client                                                                                                                                           
#
# © 2015 nullbleed - All rights reserved
#
# Unauthorized copying of this file, via any medium is strictly prohibited
# Proprietary and confidential
# Written by Bernd Busse and Daniel Jankowski, 09.06.2015

import urwid
import socket as sock
from threading import Thread, Event
import urwid
import stcpc_crypt as crypt
import time
import base64
import argparse


PROGNAME = 'stcpc - crypt demo(beta 0.3)' 
RUN = True

class ClientSock(Thread):
    
    def __init__(self, addr, port):
        super().__init__()
        self.stop_event = Event()
        self.__server = (addr, port)
        self.sock = None
        self.__callback = None
        self.__sector = 0
        self.__haskey = False

    def __log(self, msg):
        self.__callback.handle_logging("STATUS: {0}".format(msg))

    def __shutdown(self):
        self.__sock.close()
        self.__callback.handle_server_shutdown()
        self.__callback.handle_state(False)
        self.__log('Close client socket')
        self.__callback.draw_divider()
        self.__key = None
        self.__sector = 0

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
        self.__haskey = True

    def get_sock(self):
        return self.__sock

    def send_msg(self, msg, key):
        emsg = crypt.myencrypt(msg, key, self.__sector)
        try:
            self.__sock.sendall(emsg)
            self.__sector = self.__sector + len(emsg)
        except Exception as e:
            self.__log("Cannot send message: {0}".format(e))

    def run(self):
        self.__sock = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
        try:
            self.__sock.settimeout(10.0)
            self.__sock.connect(self.__server)
            self.__sock.settimeout(4.0)
            self.__log("Connected")
        except Exception as e:
            self.__log("Cannot connect to {0}:{1}".format(*self.__server))
            self.__shutdown()
        while not self.stop_event.is_set():
            if self.__haskey:
                self.__sock.settimeout(60.0)
                try:
                    data = self.__sock.recv(4096)
                except sock.timeout:
                    self.stop_event.wait(1.0)
                    continue
                if not data:
                    self.__sock.settimeout(1)
                    self.__log("Received empty message. Closing connection...")
                    break
                elif crypt.mydecrypt(data, self.__key, self.__sector) == '\x01\x03\x03\x07':
                    self.__log("Server ist shutting down. Closing connection...")
                    break
                msg = crypt.mydecrypt(data, self.__key, self.__sector)
                self.__sector = self.__sector + len(data)
                self.__callback.handle_incoming_message(msg)
        self.__shutdown()


class MainLayout(urwid.Frame):
    
    def __init__(self, host=None, port=None, nickname=None):
        self.__walker = urwid.SimpleListWalker([])
        self.__list = urwid.ListBox(self.__walker)
        self.__input = urwid.Edit(caption="$ ")
        self.__command_mode = False
        if nickname is not None:
            self.__nick = nickname
        else:
            self.__nick = 'anonym'

        list_cont = urwid.LineBox(self.__list, title=PROGNAME)
        input_cont = urwid.LineBox(self.__input)

        super().__init__(list_cont, footer=input_cont, focus_part='footer')

        self.__connection = None
        self.__last_command_failed = False
        
        self.__walker.append(urwid.Text(('logo',"        __                                  "), urwid.CENTER))
        self.__walker.append(urwid.Text(('logo',"      /\\ \\__                              "), urwid.CENTER))
        self.__walker.append(urwid.Text(('logo',"   ____\\ \\ ,_\\   ___   _____     ___        "), urwid.CENTER))
        self.__walker.append(urwid.Text(('logo',"  /',__\\\\ \\ \\/  /'___\\/\\ '__`\\  /'___\\      "), urwid.CENTER))
        self.__walker.append(urwid.Text(('logo'," /\\__, `\\\\ \\ \\_/\\ \\__/\\ \\ \\L\\ \\/\\ \\__/      "), urwid.CENTER))
        self.__walker.append(urwid.Text(('logo'," \\/\\____/ \\ \\__\\ \\____\\\\ \\ ,__/\\ \\____\\     "), urwid.CENTER))
        self.__walker.append(urwid.Text(('logo',"  \\/___/   \\/__/\\/____/ \\ \\ \\/  \\/____/     "), urwid.CENTER))
        self.__walker.append(urwid.Text(('logo',"                         \\ \\_\\              "), urwid.CENTER))
        self.__walker.append(urwid.Text(('logo',"                                           \\/_/       (beta 0.3 - crypt demo)"), urwid.CENTER))
        self.__walker.append(urwid.Text("", urwid.CENTER))

        if host and port:
            print('Connecting...',)
            self.connect(host, port)
            self.__input.set_caption('{0}> '.format(self.__nick))

    def __shutdown(self):
        self.handle_logging("Closing connections...")
        global RUN
        RUN = False
        time.sleep(1)
        self.handle_logging("Shutting down...")
        if self.__connection:
            self.__connection.get_event().set()
            self.__connection.join()
        raise urwid.ExitMainLoop()

    def __parse_input(self):
        inp = self.__input.get_edit_text()
        
        self.__input.set_edit_text("")

        # commands
        if self.__command_mode:
            if inp.strip() == 'exit':
                self.__shutdown()
            elif inp.startswith('connect'):
                ar = inp.split(' ')
                if not len(ar) == 3:
                    self.__walker.append(urwid.Text(('error', u"Not enough args"), urwid.CENTER))
                    self.__command_mode = False
                    self.__input.set_caption('{0}> '.format(self.__nick))
                    return
                else:
                    self.connect(ar[1], int(ar[2]))
                    self.__command_mode = False
                    self.__input.set_caption('{0}> '.format(self.__nick))
                    return
            elif inp.strip() == 'disconnect':
                self.disconnect()
                self.__command_mode = False
                self.__input.set_caption('$ ')
                return
            elif inp.startswith('set'):
                if inp.startswith('set nick'):
                    ar = inp.split(' ')
                    if not len(ar) == 3:
                        self.__walker.append(urwid.Text(('error', u"Not enough args"), urwid.CENTER))
                        self.__command_mode = False
                        self.__input.set_caption('{0}> '.format(self.__nick))
                        return
                    else:
                        if self.__connection:
                            self.__connection.send_msg('\x09\x09{0}'.format(ar[2]) , self.__key)
                            self.__walker.append(urwid.Text(('status', 'Changed your Nickname'), urwid.CENTER))
                            self.__command_mode = False
                            self.__nick = ar[2]
                            self.__input.set_caption('{0}> '.format(self.__nick))
                            return
                        else:
                            self.__walker.append(urwid.Text(('error', u"No connection to server"), urwid.CENTER))
                            self.__command_mode = False
                            self.__input.set_caption('$ ')
            else:
                self.__input.set_edit_text("WRONG COMMAND")
                if self.__connection:
                    self.__input.set_caption("{0}> ".format(self.__nick))
                    self.__command_mode = False
                    self.__last_command_failed = True
                    return
                else:
                    self.__input.set_caption("$ ")
                    self.__command_mode = False
                    self.__last_command_failed = True
                    return
        self.__send_msg(inp)

    def __send_msg(self, msg):
        if self.__connection:
            self.__connection.send_msg(msg, self.__key)
            self.__walker.append(urwid.Text(('sent',msg), urwid.RIGHT))
            pos = len(self.__walker)
            self.__list.set_focus(pos - 1)

    def handle_logging(self, msg):
        self.__walker.append(urwid.Text(('status',msg), urwid.CENTER))
        pos = len(self.__walker) 
        self.__list.set_focus(pos - 1)

    def handle_incoming_message(self, msg):
        self.__walker.append(urwid.Text(('incoming',msg), urwid.LEFT))
        pos = len(self.__walker) 
        self.__list.set_focus(pos - 1)

    def handle_state(self, alive):
        if not alive:
            self.__connection = None
    
    def handle_server_shutdown(self):
        self.__input.set_caption('$ ')

    def draw_divider(self):
        self.__walker.append(urwid.Divider('\u2500'))

    def connect(self, addr, port):
        if not self.__connection:
            # Connect to server
            self.handle_logging("Connecting to {0}:{1}".format(addr,str(port)))
            self.__connection = ClientSock(addr, port)
            self.__connection.set_callback(self)
            self.__connection.start()
            time.sleep(1)
            self.handle_logging("Negotiating key...")
            self.__key = self.__connection.negotiate_key() 
            self.__connection.set_haskey()
            self.__input.set_caption('{0}> '.format(self.__nick))
            self.__walker.append(urwid.Divider('\u2500'))
            if self.__nick is not None:
                self.__connection.send_msg('\x09\x09{0}'.format(self.__nick),self.__key)

    def disconnect(self):
        if self.__connection is not None:
            self.handle_logging("Disconnecting...")
            self.__connection.get_event().set()
            self.__connection.join()
            self.__connection = None
            self.__walker.append(urwid.Divider('\u2500'))

    def keypress(self, size, key):
        if self.__last_command_failed:
            self.__input.set_edit_text("")
            self.__last_command_failed = False
        
        if key == 'enter':
            self.__parse_input()
            return
        elif key == 'esc':
            if self.__command_mode:
                self.__command_mode = False
                if self.__connection:
                    self.__input.set_caption('> ')
                    self.__input.set_edit_text('')
                    return
                else:
                    self.__input.set_caption('$ ')
                    self.__input.set_edit_text('')
                    return
            self.handle_logging('Exiting...')
            self.__shutdown()
        elif key == 'page up':
            self.__list.keypress(size,'up')
            return
        elif key == 'page down':
            self.__list.keypress(size, 'down')
            return
        elif key == ':':
            if len(self.__input.get_edit_text()) == 0:
                self.__input.set_caption(':')
                self.__command_mode = True
                return

        return super().keypress(size, key)


def refresh_screen(mainloop):
    time.sleep(5)
    while RUN:
        mainloop.draw_screen()
        time.sleep(1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-H','--host', type=str)
    parser.add_argument('-p','--port', type=int)
    parser.add_argument('-l','--localhost', action='store_true')
    parser.add_argument('-n','--nick', type=str)
    parser.add_argument('-g','--generate', action='store_true', help='Generates new primes')
    args = parser.parse_args()
    
    host, port = None, None
    if args.generate:
        print('Generating new primes...')
        crypt.genprime_client()
        return True
    if args.localhost:
        host,port = '127.0.0.1', 1337
    if args.host and args.port:
        host,port = args.host, args.port       
    if args.nick:
        nickname = args.nick
    else:
        nickname = None

    palette = [
        ('normal', 'white', 'black'),
        ('error', 'light red', 'black'),
        ('warning', 'yellow', 'black'),
        ('logo', 'light blue', 'black'),
        ('status', 'dark gray', 'black'),
        ('sent', 'black', 'dark green'),
        ('incoming','black','light gray'),
            ]
    
    main_layout = MainLayout(host, port, nickname)
    
    loop = urwid.MainLoop(main_layout, palette, screen=urwid.raw_display.Screen())
    refresh = Thread(target=refresh_screen, args=(loop,))
    refresh.start()
    loop.run()


if __name__ == '__main__':
    main()
