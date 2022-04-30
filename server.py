import socket
import threading
import time


def encrypt(message: str, key, base=8):
    message = int(''.join([bin(ord(char))[2:].rjust(8, '0') for char in message]), 2)
    return pow(message, key[1], key[0])


class Server:

    def __init__(self, port: int) -> None:
        self.host = '127.0.0.1'
        self.port = port
        self.clients = []
        self.username_lookup = {}
        self.user_keys = {}
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with open("count.txt", mode='w') as file:
            file.write('0')

    def start(self):
        self.s.bind((self.host, self.port))
        self.s.listen(100)

        while True:
            c, addr = self.s.accept()
            username = c.recv(1024).decode()
            print(f"{username} tries to connect")
            self.broadcast(f'**{username} has just joined**')
            self.username_lookup[c] = username
            self.clients.append(c)

            # receiving client's public key to store.

            public_key = c.recv(1024).decode()
            public_key = tuple(map(int, public_key.split(' ')))
            print(f"Public key received from {username}:",  public_key)
            self.user_keys[username.split(' ')[1]] = public_key

            # encrypt the secret with the clients public key

            # ...

            # send the encrypted secret to a client

            # ...

            threading.Thread(target=self.handle_client, args=(c, addr,)).start()

    def broadcast(self, msg: str):
        for num, client in enumerate(self.clients):
            # encrypt the message

            enc_msg = str(encrypt(msg, self.user_keys[str(num)]))

            client.send(enc_msg.encode())

    def handle_client(self, c: socket, addr):
        # TODO: MESSAGE INTEGRITY!
        while True:
            receiver = c.recv(1024).decode()
            time.sleep(0.1)
            msg = c.recv(1024).decode()
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
                        client.send(enc_msg.encode())


if __name__ == "__main__":
    s = Server(9001)
    s.start()
