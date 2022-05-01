import socket
import threading
import random
import time

from rsa import get_random_prime


class Client:

    def __init__(self, server_ip: str, port: int, username: str) -> None:
        self.server_ip = server_ip
        self.port = port
        self.username = username
        self.s = None
        self.public_key = None
        self._private_key = None

    def _generate_keys(self, bits=512):
        p, q = get_random_prime(bits), get_random_prime(bits)
        n = p * q
        phi = (p - 1) * (q - 1)
        while True:
            try:
                e = random.choice([5, 17, 257, 65537])
                d = pow(e, -1, phi)
                break
            except:
                continue
        self.public_key = (n, e)
        self._private_key = (n, d)
        # print(self._private_key)

    def _encrypt(self, message: str, key, base=8):
        assert self.public_key is not None
        assert self._private_key is not None
        message = int(''.join([bin(ord(char))[2:].rjust(8, '0') for char in message]), 2)
        return pow(message, key[1], key[0])

    def _decrypt(self, encrypted: int, base=8):
        m = pow(encrypted, self._private_key[1], self._private_key[0])
        message = bin(m)[2:]
        rem = base - (len(message) % base)
        message = '0' * rem + message
        chunks = [message[i:i + base] for i in range(0, len(message), base)]
        message = ''.join([chr(int(item, 2)) for item in chunks])
        return message

    def init_connection(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.s.connect((self.server_ip, self.port))
        except Exception as e:
            print("[client]: could not connect to server: ", e)
            return
        print('-' * 30)
        print("**You've just entered the chat**")
        print(f"Your username is {self.username}.")
        print('-' * 30)
        self.s.send(self.username.encode())

        # receiving server keys
        server_key = self.s.recv(1024).decode()
        n, e = server_key.replace('(', '').replace(')', '').split(', ')
        n, e = int(n), int(e)
        self.server_key = n, e
        # print(server_key)

        # create key pairs
        self._generate_keys()

        # exchange public keys
        self.s.send((str(self.public_key[0]) + ' ' + str(self.public_key[1])).encode())

        # receive the encrypted secret key
        message_handler = threading.Thread(target=self.read_handler, args=())
        message_handler.start()
        input_handler = threading.Thread(target=self.write_handler, args=())
        input_handler.start()

    def read_handler(self):
        while True:
            message = self.s.recv(1024).decode()

            # decrypt message with the secret key

            message = self._decrypt(int(message))

            print(message)

    def send_to_server(self, msg: str):
        msg = self._encrypt(msg, self.server_key)
        self.s.send(str(msg).encode())

    def write_handler(self):
        # TODO: MESSAGE INTEGRITY!
        while True:
            message = self.username + ': ' + input()

            # encrypt message with the public key of the server
            # message = str(self._encrypt(message, self.server_key))

            # Now message is an integer represented by a string
            message = message.split(' | ')
            if len(message) == 1:
                message = message[0]
                receiver = ' '
            else:
                message, receiver = message[0], message[1].strip()
            self.s.send(receiver.encode())
            self.send_to_server(message)
            # self.s.send(message.encode())


if __name__ == "__main__":
    # count = 0
    with open("count.txt", mode='r') as file:
        count = int(file.readlines()[0])
    with open("count.txt", mode='w') as file:
        file.write(str(count + 1))
    cl = Client("127.0.0.1", 9001, "user " + str(count))
    cl.init_connection()
