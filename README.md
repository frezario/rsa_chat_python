# RSA CHAT

A simple multi-core chat that involves the usege of RSA encryption.

Based on textbook RSA.

To run, simply execute the server.py and then client.py-s one by one.

Then, just type some text into one of the user terminals and enjoy the result.

# HOW IT WORKS?

Suppose user Alice wants to send secret message to user Bob. Then, we might want to build a protected connection between both of users.

This protected connection is our server.

The algorithm is the following:

1. A server and Alice exchange public keys: server receives Alice public kay and Alice receives server public key.
2. The same goes for Bob.
3. Alice encrypts the message using server public key and somehow shows that it is for Bob. In our case, we chose <message> | <id> format to show that message <message> should be delivered to the client with id <id>.
4. Server receives the message, decrypts it using it's own private key.
5. Server decrypts the message using Bob's public key and sends it to Bob.
6. Bob receives encrypted message using his private key and now can read the secret.

If <id> wasn't specified, we simply show message to all receivers.

The example of usage:

![usage](https://user-images.githubusercontent.com/91615650/166143608-5bf3b5ca-56d4-4112-994d-6d8f8bd8e77d.png)
