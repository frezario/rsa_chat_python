import socket
import threading
import random
from test import get_random_prime


# from server import s


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

        self.s.send(self.username.encode())

        # create key pairs
        self._generate_keys()
        # exchange public keys

        # receive the encrypted secret key

        message_handler = threading.Thread(target=self.read_handler, args=())
        message_handler.start()
        input_handler = threading.Thread(target=self.write_handler, args=())
        input_handler.start()

    def read_handler(self):
        while True:
            message = self.s.recv(1024).decode()

            # decrypt message with the secret key

            # ... 

            print(message)

    def write_handler(self):
        while True:
            message = self.username + ': ' + input()

            # encrypt message with the public key

            # ...

            self.s.send(message.encode())


if __name__ == "__main__":
    count = 0
    with open("count.txt", mode='r') as file:
        count = int(file.readlines()[0])
    with open("count.txt", mode='w') as file:
        file.write(str(count + 1))
    cl = Client("127.0.0.1", 9001, "user" + str(count))
    cl.init_connection()
    input()