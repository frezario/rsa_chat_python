import socket
import threading
import random
from rsa import get_random_prime


def encrypt(message: str, key, base=8):
    """
    Encrypts a message using receiver's public key.
    :param message: a message to encrypt.
    :param key: receiver's public key.
    :param base: how many bits does a symbol contain.
    :return: a decrypted integer.
    """
    message = int(''.join([bin(ord(char))[2:].rjust(base, '0') for char in message]), 2)
    return pow(message, key[1], key[0])


class Server:
    """
    Server class implementation.
    """

    def __init__(self, port: int) -> None:
        self.host = '127.0.0.1'
        self.port = port
        self.clients = []
        self.username_lookup = {}
        self.user_keys = {}
        self.public_key = None
        self._private_key = None
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with open("count.txt", mode='w') as file:
            file.write('0')

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
        # print(self._private_key)

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

    def start(self):
        """
        Initiates the key exchange between the server and a client.
        :return: nothing
        """
        self.s.bind((self.host, self.port))
        self.s.listen(100)
        self._generate_keys()
        while True:
            # Receiving user and his username
            c, addr = self.s.accept()
            username = c.recv(1024).decode()
            print(f"{username} tries to connect")
            self.broadcast(f'**{username} has just joined**')
            self.username_lookup[c] = username
            self.clients.append(c)

            # sending public key of the server to the client
            c.send(str(self.public_key).encode())

            # receiving client's public key to store.

            public_key = c.recv(1024).decode()
            public_key = tuple(map(int, public_key.split(' ')))
            # print(f"Public key received from {username}:", public_key)
            self.user_keys[username.split(' ')[1]] = public_key

            threading.Thread(target=self.handle_client, args=(c, addr,)).start()

    def broadcast(self, msg: str):
        """
        Sends a message to each of users.
        :param msg:
        :return:
        """
        for num, client in enumerate(self.clients):
            # encrypt the message

            enc_msg = str(encrypt(msg, self.user_keys[str(num)]))

            client.send(enc_msg.encode())

    def handle_client(self, c: socket, addr):
        """
        Handles message, received from the client.
        :param c: a client socket
        :param addr: the addres of the client.
        :return: nothing
        """
        while True:
            receiver = c.recv(1024).decode()
            # Encrypting the message
            msg = c.recv(1024).decode()
            msg_hash, msg = msg.split(' | ')
            msg = self._decrypt(int(msg))
            try:
                # For the one specific receiver
                msg = str(encrypt(msg, self.user_keys[receiver]))
                self.clients[int(receiver)].send(msg.encode())

                for num, client in enumerate(self.clients):
                    if client != c and num != int(receiver):
                        message = f"user {self.clients.index(c)} tells user {receiver} the secret!"
                        message = str(encrypt(message, self.user_keys[str(num)]))
                        client.send(message.encode())
            except Exception as err:
                # For the whole community
                # self.broadcast(f"I was failed, {repr(receiver)}")
                # self.broadcast(str(self.user_keys.keys()))
                for num, client in enumerate(self.clients):
                    if client != c:
                        enc_msg = str(encrypt(msg, self.user_keys[str(num)]))
                        client.send(enc_msg.encode() + ' | '.encode() + msg_hash.encode())


if __name__ == "__main__":
    s = Server(9001)
    s.start()
