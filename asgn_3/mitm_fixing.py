import random
import sys
from multiprocessing.spawn import import_main_path

from Crypto.Hash import SHA256

from diffie_hellman import get_public_key, get_secret_key
from globals import GLOBAL_BASE_G, GLOBAL_IV, GLOBAL_MOD_P


def main():
    GLOBAL_MOD_P = 7
    GLOBAL_BASE_G = 7 * 3 * 7
    # ^^ This speeds up runtime a lot.

    # alice chooses secret int a
    alice_a = 4
    # bob chooses secret int b
    bob_b = 3

    A = get_public_key(alice_a.to_bytes(), GLOBAL_BASE_G, GLOBAL_MOD_P)
    B = get_public_key(bob_b.to_bytes(), GLOBAL_BASE_G, GLOBAL_MOD_P)

    # print(int.from_bytes(A))
    # print(int.from_bytes(B))

    ###### MALLORY ####################
    A = B = GLOBAL_BASE_G.to_bytes(
        (GLOBAL_BASE_G.bit_length() + 7) // 8
    )  # send q to both B and A
    ###################################

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


if __name__ == "__main__":
    main()
