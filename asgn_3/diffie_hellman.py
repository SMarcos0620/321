from random import randbytes

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

GLOBAL_MOD_P = 23
GLOBAL_BASE_G = 5


def get_secret_key(their_private_key: bytes, my_public_key: bytes, prime: int) -> bytes:
    """
    s = A^b mod p
    """

    return bytes(int(my_public_key) ** int(their_private_key) % prime)


def get_public_key(private_key: bytes, base: int, prime: int) -> bytes:
    """
    A = g^a mod p
    """
    val = (base ** int(private_key)) % prime
    return bytes(val)


def main():
    message = "Hello world"
    IV = randbytes(16)

    cipher = AES.new()

    pass


if __name__ == "__main__":
    main()
