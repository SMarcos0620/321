import sys

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad

from diffie_hellman import get_public_key, get_secret_key
from globals import GLOBAL_IV, GLOBAL_MOD_Q, GLOBAL_BASE_α

TASK_1 = True

_ = GLOBAL_MOD_Q  # make ruff happy here
_ = GLOBAL_BASE_α


def main():
    global GLOBAL_BASE_α
    global GLOBAL_MOD_Q

    # p = q
    GLOBAL_MOD_Q = 7
    # g = a
    # GLOBAL_BASE_G = 7 * 3 * 7
    # GLOBAL_BASE_G = 1
    # GLOBAL_BASE_G = GLOBAL_MOD_P
    GLOBAL_BASE_α = GLOBAL_MOD_Q - 1
    # ^^ This speeds up runtime a lot.

    # alice chooses secret int a
    alice_a = 4
    # bob chooses secret int b
    bob_b = 3

    A = get_public_key(alice_a.to_bytes(), GLOBAL_BASE_α, GLOBAL_MOD_Q)
    B = get_public_key(bob_b.to_bytes(), GLOBAL_BASE_α, GLOBAL_MOD_Q)

    # print(int.from_bytes(A))
    # print(int.from_bytes(B))

    ###### MALLORY ####################
    # let M be Mallory's prime
    if TASK_1:
        A = B = M = GLOBAL_MOD_Q.to_bytes((GLOBAL_MOD_Q.bit_length() + 7) // 8)
    # send q to both Bob and Alice
    # essentially makes the secret key computation: q mod q = 0
    ###################################

    # Alice computes s = Ba mod p
    secret_key_alice = get_secret_key(alice_a.to_bytes(), B, GLOBAL_MOD_Q)
    sa = int.from_bytes(secret_key_alice)
    # bob computes s = Aa mod p
    secret_key_bob = get_secret_key(bob_b.to_bytes(), A, GLOBAL_MOD_Q)
    sb = int.from_bytes(secret_key_bob)
    # Alice and bob now share a secret number s

    ###### MALLORY ####################
    # Mallory can now determine s, which is the secret key

    # Mallory's secret int
    if TASK_1:
        mallory_m = 5
        secret_key_mallory = get_secret_key(mallory_m.to_bytes(), M, GLOBAL_MOD_Q)
        sm = int.from_bytes(secret_key_mallory)
    ###################################

    if TASK_1:
        print(
            f"""Shared secret keys s [Alice, Bob, Mallory]:
            {sa} == {sb} == {sm} ? {sa == sb == sm}\n"""
        )
        if sa != sb != sm:
            print("shared secret keys are not identical")
            sys.exit()
    else:
        print(
            f"""Shared secret keys s [Alice, Bob, Mallory]:
            {sa} == {sb} ? {sa == sb}\n"""
        )
        if sa != sb:
            print("shared secret keys are not identical")
            sys.exit()

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

    ###### MALLORY ####################
    if TASK_1:
        km = SHA256.new()
        km.update(secret_key_mallory)
        km_bytes = km.digest()
        trunc_km = bytearray(km_bytes)[:16]
    ###################################

    if TASK_1:
        print(
            f"""Computed symmetric keys k [Alice, Bob, Mallory]:
            {trunc_ka} == {trunc_kb} == {trunc_km} ? {trunc_ka == trunc_kb == trunc_km}"""
        )
        # check if the symmetric keys are the same
        if trunc_ka != trunc_kb != trunc_km:
            print("symmetic keys are not the same")
            sys.exit()
    else:
        print(
            f"""Computed symmetric keys k [Alice, Bob, Mallory]:
            {trunc_ka} == {trunc_kb} ? {trunc_ka == trunc_kb}"""
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

    ###### MALLORY ####################
    # CALCULATED_KEY = trunc_sa = trunc_sb = trunc_km
    # trunc_km is used here for clarity
    if TASK_1:
        cipher_decrypt_mallory_from_bob = AES.new(trunc_km, AES.MODE_CBC, GLOBAL_IV)
        plaintext_intercepted_by_mallory_from_bob = unpad(
            cipher_decrypt_mallory_from_bob.decrypt(ciphertext_from_bob), AES.block_size
        )

        cipher_decrypt_mallory_from_alice = AES.new(trunc_km, AES.MODE_CBC, GLOBAL_IV)
        plaintext_intercepted_by_mallory_from_alice = unpad(
            cipher_decrypt_mallory_from_alice.decrypt(ciphertext_from_alice),
            AES.block_size,
        )
    ###################################

    # verification
    print(
        f"\nAlice sent: {message_from_alice}\nAlice recieved: {plaintext_recieved_by_alice}"
    )
    print(
        f"  Verify message sent by Bob to Alice [Alice, Bob]: {message_from_bob} == {plaintext_recieved_by_alice} ? {message_from_bob == plaintext_recieved_by_alice}"
    )
    print(f"\nBob sent: {message_from_bob}\nBob recieved: {plaintext_recieved_by_bob}")
    print(
        f"  Verify message sent by Alice to Bob [Alice, Bob]: {message_from_alice} == {plaintext_recieved_by_bob} ? {message_from_alice == plaintext_recieved_by_bob}"
    )

    ###### MALLORY ####################
    if TASK_1:
        print(
            f"""
    Mallory intercepted Alice's message: {plaintext_intercepted_by_mallory_from_alice}
        Verify that message Alice sent is the same as the intercepted one [Alice, Mallory]: {message_from_alice} == {plaintext_intercepted_by_mallory_from_alice} ? {message_from_alice == plaintext_intercepted_by_mallory_from_alice}

    Mallory intercepted Bob's message: {plaintext_intercepted_by_mallory_from_bob}
        Verify that message Bob sent is the same as the intercepted one [Bob, Mallory]: {message_from_bob} == {plaintext_intercepted_by_mallory_from_bob} ? {message_from_bob == plaintext_intercepted_by_mallory_from_bob}

        """
        )
    ###################################

    ###### TASK 2 #####################
    # Repeat this attack, but instead of tampering with YA and YB, tamper with the
    # generator GLOBAL_BASE_G. Show that Mallory can recover Alice and Bob's messages
    # from their ciphertexts by setting GLOBAL_BASE_G to 1, q, or q-1.

    pass


if __name__ == "__main__":
    main()
