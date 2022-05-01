import socket
import threading
import random
import hashlib

from rsa import get_random_prime


class Client:
    """
    Client class implementation.
    """

    def __init__(self, server_ip: str, port: int, username: str) -> None:
        self.server_ip = server_ip
        self.port = port
        self.username = username
        self.s = None
        self.public_key = None
        self._private_key = None

    def _generate_keys(self, bits=512):
        """
        Generates key pair.
        Primes are selected close to 2 ** bits.
        :param bits: how many bits we want to have.
        :return: nothing
        """
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
        """
        Encrypts a message using receiver's public key.
        :param message: a message to encrypt.
        :param key: receiver's public key.
        :param base: how many bits does a symbol contain.
        :return: a decrypted integer.
        """
        assert self.public_key is not None
        assert self._private_key is not None
        message = int(''.join([bin(ord(char))[2:].rjust(base, '0') for char in message]), 2)
        return pow(message, key[1], key[0])

    def _decrypt(self, encrypted: int, base=8):
        """
        Decrypts a received integer into a message.
        :param encrypted: an integer that was received by the _encrypt().
        :param base: how many bits does a symbol contain.
        :return: a decoded message.
        """
        m = pow(encrypted, self._private_key[1], self._private_key[0])
        message = bin(m)[2:]
        rem = base - (len(message) % base)
        message = '0' * rem + message
        chunks = [message[i:i + base] for i in range(0, len(message), base)]
        message = ''.join([chr(int(item, 2)) for item in chunks])
        return message

    def init_connection(self):
        """
        Sets a connection between server and user.
        :return: nothing
        """
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

        # create key pairs
        self._generate_keys()

        # exchange public keys
        self.s.send((str(self.public_key[0]) + ' ' + str(self.public_key[1])).encode())

        # receive the encrypted secret key
        message_handler = threading.Thread(target=self.read_handler, args=())
        message_handler.start()
        input_handler = threading.Thread(target=self.write_handler, args=())
        input_handler.start()

    @staticmethod
    def check_integrity(received_hash: bytes, msg: str):
        real_hash = hashlib.sha224(msg.encode()).hexdigest()
        if received_hash == '':
            return True
        return received_hash == real_hash


    def read_handler(self):
        """
        Handles the incoming message.
        :return: nothing
        """
        while True:
            message = self.s.recv(1024).decode()
            hash_and_message = message.split(' | ')
            message = hash_and_message[0]
            message = self._decrypt(int(message))
            if len(hash_and_message) != 1:
                msg_hash = hash_and_message[1]
                assert self.check_integrity(msg_hash, message), 'ERROR, message are changed!'
            print(message)

    def send_to_server(self, msg: str):
        """
        Sends a string message to the server through the
        protected channel.
        """
        msg_hash = hashlib.sha224(msg.encode()).hexdigest()
        msg = self._encrypt(msg, self.server_key)
        self.s.send(msg_hash.encode() + ' | '.encode() + str(msg).encode())

    def write_handler(self):
        """
        Handles user input.
        :return: nothing
        """
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


if __name__ == "__main__":
    # count = 0
    with open("count.txt", mode='r') as file:
        count = int(file.readlines()[0])
    with open("count.txt", mode='w') as file:
        file.write(str(count + 1))
    cl = Client("127.0.0.1", 9001, "user " + str(count))
    cl.init_connection()
