from random import randbytes

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

GLOBAL_MOD_P = 23
GLOBAL_BASE_G = 5


def get_secret_key(my_private_key: bytes, thier_public_key: bytes, prime: int) -> bytes:
    """
    s = A^b mod p
    """

    return (
        int.from_bytes(thier_public_key) ** int.from_bytes(my_private_key) % prime
    ).to_bytes()


def get_public_key(private_key: bytes, base: int, prime: int) -> bytes:
    """
    A = g^a mod p
    """
    val = (base ** int.from_bytes(private_key)) % prime
    return val.to_bytes()


def main():
    # alice chooses secret int a
    alice_a = 4
    # bob chooses secret int b
    bob_b = 3

    A = get_public_key(alice_a.to_bytes(), GLOBAL_BASE_G, GLOBAL_MOD_P)
    B = get_public_key(bob_b.to_bytes(), GLOBAL_BASE_G, GLOBAL_MOD_P)

    print(int.from_bytes(A))
    print(int.from_bytes(B))

    #Alice computes s = Ba mod p
    secret_key_alice = get_secret_key(alice_a.to_bytes(), B, GLOBAL_MOD_P)
    sa = int.from_bytes(secret_key_alice)
    #bob computes s = Aa mod p
    secret_key_bob = get_secret_key(bob_b.to_bytes(), A, GLOBAL_MOD_P)
    sb = int.from_bytes(secret_key_bob)
    #Alice and bob now share a secret number s
    print("Shared secret key s: ", end = '')
    print(f"{sa} == {sb} ? {sa == sb}")

    #symmetric key, k = SHA 256(s)
    #ka = key alice; kb = key bob
    #Documentation: https://pycryptodome.readthedocs.io/en/latest/src/hash/sha256.html

    #create an sha256 object, hash the data from secret_key_alice/bob, turn it into binary form/byte string, turn it into a byte array, truncate 16 bytes
    ka = SHA256.new()
    ka.update(secret_key_alice)
    ka_bytes = ka.digest()
    trunc_ka = bytearray(ka_bytes)[:16]
    kb = SHA256.new()
    kb.update(secret_key_bob)
    kb_bytes = kb.digest()
    trunc_kb = bytearray(kb_bytes)[:16]


    print("Computed symmetric keys k: ", end = '')
    print(f"{trunc_ka} == {trunc_kb} ? {trunc_ka == trunc_kb}")


    message = "Hello world"
    IV = randbytes(16)

    # cipher = AES.new()

    pass


if __name__ == "__main__":
    main()
