#!/usr/bin/env python3
import socket
import asyncore
import asynchat
import rsa
from random import getrandbits
from struct import pack
from queue import Queue, Empty
from processfile import ProcessFileThread


class async_secretconnect(asyncore.dispatcher):

    """docstring for async_secretconnect"""

    def __init__(self, port):
        super(async_secretconnect, self).__init__()
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.bind(('', port))
        self.listen(5)
        print('start listening at port %d' % port)

    def handle_accept(self):
        client, addr = self.accept()
        return async_connect_handler(client)


class async_connect_handler(asynchat.async_chat):

    """docstring for async_connect_handler"""

    def __init__(self, conn=None):
        super(async_connect_handler, self).__init__(conn)
        self.data = []
        self.push(
            b'connect success!! \n welcome to secret communction system!! \n first you should be_authorized! \n')
        self.set_terminator(b'\x04\x04\x04')
        self.time = 0
        self.process_seq = [self.first_process, self.second_process]
        self.process_file = False
        self.input_queue = Queue()

    def collect_incoming_data(self, data):
        if not self.process_file:
            self.data.append(data)
        else:
            self.input_queue.put(data)

    def found_terminator(self):
        print(self.data)
        res = b''.join(self.data)
        self.data = res.split(b'\r\n')
        print(self.time)
        try:
            self.process_seq[self.time]()
        except IndexError:
            self.default_process()
        self.data = []
        self.time += 1

    def first_process(self):
        print(self.data)
        self.random_1 = self.data[0]
        self.pubkey_name = self.data[1]
        pubkey, privkey = rsa.newkeys(512, poolsize=8)
        self.pubkey = pubkey
        self.privkey = privkey
        print("pubkey: %s" % pubkey)
        self.random_2 = self.generate_random()
        self.push(pubkey.save_pkcs1())
        self.push(b'\r\n')
        client_pubkey = self.get_client_pubkey()
        print(client_pubkey)
        if client_pubkey:
            self.push(rsa.encrypt(self.random_2, client_pubkey))
            self.push(b'\x04\x04\x04')

    def second_process(self):
        # print (self.random_2)
        # print (self.d)
        if rsa.decrypt(self.data[0], self.privkey) != self.random_2:
            self.push('认证失败\x04\x04\x04'.encode('utf8'))
            self.close_when_done()
        else:
            self.random_3 = rsa.decrypt(self.data[1], self.privkey)
            self.random = self.random_1 + self.random_2 + self.random_3
            self.iv = self.generate_random()
            self.push(rsa.encrypt(self.iv, self.client_pubkey))
            self.push(b'\r\n')
            self.push(
                b'connection established!! now you can upload or download file\x04\x04\x04')
            print(self.random)
            print(self.iv)

    def default_process(self):
        if self.process_file:
            self.process_file = False
            return
        commender = self.data[0].decode('utf8').split()
        try:
            getattr(self, "commender_%s" % commender[0])(*commender[1:])
        except AttributeError:
            self.push('commend not found')

    def commender_close(self, *args):
        self.close()

    def commender_upload(self, *args):
        print('i am running ')
        self.process_file = True
        p = ProcessFileThread(
            args[0], 'w', self.random, self.iv, self.input_queue)
        p.start()
        return p

    def commender_download(self, *args):
        self.output_queue = Queue()
        p = ProcessFileThread(
            args[0], 'r', self.random, self.iv, self.output_queue)
        p.start()
        while True:
            try:
                data = self.output_queue.get(timeout=1)
            except Empty:
                break
            print(data)
            self.push(data)
        self.push(b'\x04\x04\x04')
        p.join()

    def get_client_pubkey(self):
        if not hasattr(self, 'client_pubkey'):
            try:
                with open(self.pubkey_name, 'rb') as privatefile:
                    keydate = privatefile.read()
            except FileNotFoundError:
                # print('i have run')
                error = '''名称为"'''.encode('utf8') + self.pubkey_name + \
                    '''"的公钥文件不存在\n 连接将要关闭\x04\x04\x04'''.encode('utf8')
                # print(error)
                self.push(error)
                self.close_when_done()
                return None

            self.client_pubkey = rsa.PublicKey.load_pkcs1(keydate)
        return self.client_pubkey

    def generate_random(self):
        return pack('Q', getrandbits(64))


if __name__ == '__main__':
    a = async_secretconnect(8080)
    asyncore.loop()
