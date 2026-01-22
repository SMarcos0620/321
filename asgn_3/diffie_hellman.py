import sys

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from globals import GLOBAL_BASE_G, GLOBAL_IV, GLOBAL_MOD_P

CALCULATED_KEY = 0


def get_secret_key(my_private_key: bytes, thier_public_key: bytes, prime: int) -> bytes:
    """
    s = A^b mod p
    """
    val = int(
        int.from_bytes(thier_public_key) ** int.from_bytes(my_private_key) % prime
    )
    # compute appropriate bit length and resize accordingly
    byte_length = (val.bit_length() + 7) // 8
    return val.to_bytes(byte_length, byteorder="big")


def get_public_key(private_key: bytes, base: int, prime: int) -> bytes:
    """
    A = g^a mod p
    """
    val = int((base ** int.from_bytes(private_key)) % prime)
    # compute appropriate bit length and resize accordingly
    byte_length = (val.bit_length() + 7) // 8
    return val.to_bytes(byte_length, byteorder="big")


def main():
    # alice chooses secret int a
    alice_a = 4
    # bob chooses secret int b
    bob_b = 3

    A = get_public_key(alice_a.to_bytes(), GLOBAL_BASE_G, GLOBAL_MOD_P)
    B = get_public_key(bob_b.to_bytes(), GLOBAL_BASE_G, GLOBAL_MOD_P)

    print(int.from_bytes(A))
    print(int.from_bytes(B))

    # Alice computes s = Ba mod p
    secret_key_alice = get_secret_key(alice_a.to_bytes(), B, GLOBAL_MOD_P)
    sa = int.from_bytes(secret_key_alice)
    # bob computes s = Aa mod p
    secret_key_bob = get_secret_key(bob_b.to_bytes(), A, GLOBAL_MOD_P)
    sb = int.from_bytes(secret_key_bob)
    # Alice and bob now share a secret number s
    print("Shared secret key s: ", end="")
    print(f"{sa} == {sb} ? {sa == sb}")

    # symmetric key, k = SHA 256(s)
    # ka = key alice; kb = key bob
    # Documentation: https://pycryptodome.readthedocs.io/en/latest/src/hash/sha256.html

    # create an sha256 object, hash the data from secret_key_alice/bob, turn it into binary form/byte string, turn it into a byte array, truncate 16 bytes
    ka = SHA256.new()
    ka.update(secret_key_alice)
    ka_bytes = ka.digest()
    trunc_ka = bytearray(ka_bytes)[:16]

    kb = SHA256.new()
    kb.update(secret_key_bob)
    kb_bytes = kb.digest()
    trunc_kb = bytearray(kb_bytes)[:16]

    print(
        f"Computed symmetric keys k: {trunc_ka} == {trunc_kb} ? {trunc_ka == trunc_kb}"
    )

    # check if the symmetric keys are the same
    if trunc_ka != trunc_kb:
        print("symmetic keys are not the same")
        sys.exit()

    # if they are the same, then update CALCULATED_KEY
    CALCULATED_KEY = trunc_ka

    # attempt to send messages to each other
    message_from_alice = b"Hello Bob"
    message_from_bob = b"Hello Alice"

    # encrypt
    cipher_encrypt_alice = AES.new(CALCULATED_KEY, AES.MODE_CBC, GLOBAL_IV)
    ciphertext_from_alice = cipher_encrypt_alice.encrypt(
        pad(message_from_alice, AES.block_size)
    )
    cipher_encrypt_bob = AES.new(CALCULATED_KEY, AES.MODE_CBC, GLOBAL_IV)
    ciphertext_from_bob = cipher_encrypt_bob.encrypt(
        pad(message_from_bob, AES.block_size)
    )

    # decrypt
    cipher_decrypt_alice = AES.new(CALCULATED_KEY, AES.MODE_CBC, GLOBAL_IV)
    plaintext_recieved_by_alice = unpad(
        cipher_decrypt_alice.decrypt(ciphertext_from_bob), AES.block_size
    )
    cipher_decrypt_bob = AES.new(CALCULATED_KEY, AES.MODE_CBC, GLOBAL_IV)
    plaintext_recieved_by_bob = unpad(
        cipher_decrypt_bob.decrypt(ciphertext_from_alice), AES.block_size
    )

    # verification
    print(
        f"\nAlice sent: {message_from_alice}\nAlice recieved: {plaintext_recieved_by_alice}"
    )
    print(
        f"Verify message sent by Bob to Alice: {message_from_bob} == {plaintext_recieved_by_alice} ? {message_from_bob == plaintext_recieved_by_alice}"
    )
    print(f"\nBob sent: {message_from_bob}\nBob recieved: {plaintext_recieved_by_bob}")
    print(
        f"Verify message sent by Alice to Bob: {message_from_alice} == {plaintext_recieved_by_bob} ? {message_from_alice == plaintext_recieved_by_bob}"
    )

    pass


if __name__ == "__main__":
    main()
