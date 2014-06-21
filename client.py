#!/usr/bin/env python3

import socket
from random import getrandbits
from struct import pack
import time
import rsa
from queue import Queue, Empty
from processfile import ProcessFileThread


class Client(object):

    def __init__(self, host, port):
        self.s = socket.socket()
        self.s.connect((host, port))
        data = self.s.recv(1024)
        print(data.decode())
        self.establishconnect()

    def generate_random(self):
        return pack('Q', getrandbits(64))

    def establishconnect(self):
        # process 1
        self.random_1 = self.generate_random()
        self.s.send(self.random_1)
        self.s.send(b'\r\npub_client.pub\x04\x04\x04')
        # process2
        data = self.recv()
        self.server_public_key = rsa.PublicKey.load_pkcs1(data[0])
        # print(data[1])
        self.random_2 = rsa.decrypt(data[1], self.load_secret_key())
        # print(b'random_2:' + self.random_2)
        self.s.send(rsa.encrypt(self.random_2, self.server_public_key))
        self.s.send(b'\r\n')
        self.random_3 = self.generate_random()
        self.s.send(rsa.encrypt(self.random_3, self.server_public_key))
        self.s.send(b'\x04\x04\x04')
        data = self.recv()
        self.random = self.random_1 + self.random_2 + self.random_3
        self.iv = rsa.decrypt(data[0], self.load_secret_key())
        print(data[1].decode())
        print('secret:')
        print(self.random)
        print('iv:')
        print(self.iv)

    def recv(self, show=False):
        res = b''
        while True:
            tmp = self.s.recv(1024)
            res += tmp
            if b'\x04\x04\x04' in tmp:
                res = res.replace(b'\x04\x04\x04', b'')
                break
        if show:
            print(res)

        return res.split(b'\r\n')

    def load_secret_key(self):
        if not hasattr(self, 'client_privatekey'):
            with open('private_clinet', 'rb') as p:
                data = p.read()
            self.client_privatekey = rsa.PrivateKey.load_pkcs1(data)
        return self.client_privatekey

    def interactive_mode(self):
        while True:
            commender = input('put the commender type ? for help:')
            try:
                getattr(self, commender.split()[0])(commender)
            except AttributeError:
                self.show_help_info()

    def show_help_info(self):
        print('''
            upload 本地文件 远程文件 将本地文件上传到远程文件
            download 远程文件  本地文件 将远程文件上传到本机
            ''')

    def upload(self, commender):
        self.output_queue = Queue()
        commende = commender.split()
        p = ProcessFileThread(
            commende[1], 'r', self.random, self.iv, self.output_queue)
        p.start()
        self.s.send(b'upload ' + commende[2].encode() + b'\x04\x04\x04')
        while True:
            try:
                data = self.output_queue.get(timeout=1)
            except Empty:
                break
            self.s.send(data)
        p.join()
        self.s.send(b'\x04\x04\x04')
        self.s.close()

    def download(self, commender):
        self.input_queue = Queue()
        commende = commender.split()
        p = ProcessFileThread(
            commende[2], 'w', self.random, self.iv, self.input_queue)
        p.start()
        self.s.send(b'download '+ commende[1].encode() + b'\x04\x04\x04')
        while True:

            data = self.s.recv(2048)
            self.input_queue.put(data)
            if b'\x04\x04\x04' in data:
                data = data.replace(b'\x04\x04\x04', b'')
                self.input_queue.put(data)
                break

        p.join()

    def close(self, commender):
        self.s.close()
        exit()


if __name__ == '__main__':
    c = Client('127.0.0.1', 8080)
    c.interactive_mode()
