import random

# Pre generated primes
first_primes_list = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
                     31, 37, 41, 43, 47, 53, 59, 61, 67,
                     71, 73, 79, 83, 89, 97, 101, 103,
                     107, 109, 113, 127, 131, 137, 139,
                     149, 151, 157, 163, 167, 173, 179,
                     181, 191, 193, 197, 199, 211, 223,
                     227, 229, 233, 239, 241, 251, 257,
                     263, 269, 271, 277, 281, 283, 293,
                     307, 311, 313, 317, 331, 337, 347, 349]


def nBitRandom(n):
    return random.randrange(2 ** (n - 1) + 1, 2 ** n - 1)


def getLowLevelPrime(n):
    '''Generate a prime candidate divisible
    by first primes'''
    while True:
        # Obtain a random number
        pc = nBitRandom(n)

        # Test divisibility by pre-generated
        # primes
        for divisor in first_primes_list:
            if pc % divisor == 0 and divisor ** 2 <= pc:
                break
        else:
            return pc


def isMillerRabinPassed(mrc):
    '''Run 20 iterations of Rabin Miller Primality test'''
    maxDivisionsByTwo = 0
    ec = mrc - 1
    while ec % 2 == 0:
        ec >>= 1
        maxDivisionsByTwo += 1
    assert (2 ** maxDivisionsByTwo * ec == mrc - 1)

    def trialComposite(round_tester):
        if pow(round_tester, ec, mrc) == 1:
            return False
        for i in range(maxDivisionsByTwo):
            if pow(round_tester, 2 ** i * ec, mrc) == mrc - 1:
                return False
        return True

    # Set number of trials here
    numberOfRabinTrials = 20
    for i in range(numberOfRabinTrials):
        round_tester = random.randrange(2, mrc)
        if trialComposite(round_tester):
            return False
    return True


def get_random_prime(bits=512):
    while True:
        prime_candidate = getLowLevelPrime(bits)
        if not isMillerRabinPassed(prime_candidate):
            continue
        else:
            return prime_candidate


class Client:
    def __init__(self, name: str):
        self.name = name
        self.public_key = None
        self.private_key = None

    def generate_keys(self, bits=512):
        p = get_random_prime(bits)
        q = get_random_prime(bits)
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
        self.private_key = (n, d)

    def encrypt(self, message: str, key, base=8):
        assert (self.public_key is not None)
        assert (self.private_key is not None)
        message = int(''.join([bin(ord(char))[2:].rjust(8, '0') for char in message]), 2)
        # message = int(''.join(format(ord(i), '08b') for i in message), 2)
        return pow(message, key[1], key[0])

    def decrypt(self, encrypted: int, base=8):
        m = pow(encrypted, self.private_key[1], self.private_key[0])
        message = bin(m)[2:]
        rem = base - (len(message) % base)
        message = '0' * rem + message
        chunks = [message[i:i + base] for i in range(0, len(message), base)]
        message = ''.join([chr(int(item, 2)) for item in chunks])
        return message


# Bob = Client("Bob")
# Alice = Client("Alice")
# Bob.generate_keys()
# Alice.generate_keys()
# # Bob.encrypt("HELLO", Alice.public_key)
# # print(Alice.private_key)
# # print(Bob.encrypt("HELLO, SUUUUUKAA!!!!!", Alice.public_key))
# print(Alice.decrypt(Bob.encrypt("HELLO, SUUUUUKAA!!!!!", Alice.public_key)))
