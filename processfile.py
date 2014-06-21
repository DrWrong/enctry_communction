from threading import Thread
import pyDes
import queue as python_queue

class ProcessFileThread(Thread):

    def __init__(self, filename, mode, random, iv, queue, *args, **kwargs):
        self.filename = filename
        self.mode = mode
        self.queue = queue
        self.random = random
        self.iv = iv
        self.des_handler = self.des_init()
        super(ProcessFileThread, self).__init__(*args, **kwargs)

    def des_init(self):
        return pyDes.triple_des(self.random, pyDes.CBC, self.iv, padmode=pyDes.PAD_PKCS5)

    def run(self):
        if self.mode == 'w':
            self.write_file()
        if self.mode == 'r':
            self.read_file()

    def write_file(self):
        # print('i have run')
        with open(self.filename, 'wb') as f, open(self.filename + '.tmp', 'wb') as f_tmp:
            while True:
                try:
                    queue = self.queue.get(timeout=5)
                except python_queue.Empty:
                    break
                f_tmp.write(queue)
                res = self.des_handler.decrypt(queue)
                f.write(res)

    def read_file(self):
        with open(self.filename, 'rb') as f:
            while True:
                data = f.read(1024)
                if not data:
                    break
                res = self.des_handler.encrypt(data)
                self.queue.put(res)

