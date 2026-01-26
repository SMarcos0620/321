import Crypto.Math.Primality
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from globals import GLOBAL_IV, GLOBAL_MOD_Q, GLOBAL_BASE_α
import math, random
"""
Task 3: Implement “textbook” RSA & MITM Key Fixing via Malleability:
1). RSA has two core components: key generation and encryption/decryption. (90%
of the work is in implementing key generation.) Your implementation should support
variable length primes (up to 2048 bits), and use the value e=65537. Feel free to use
your cryptographic library’s interface for generating large primes, but implement the
rest - including computing the multiplicative inverse - yourself.
Encrypt and decrypt a few messages to yourself to make sure it works. Remember
messages must be integers in Z^*_n (that is, less than n, the product of the two primes).

You can convert an ASCII string to hex, and then turn that hex value into an integer.

2). From 1). you just implemented “textbook” RSA, and it is widely insecure.
Because it is too slow and inconvenient to operate on a large amount data directly,
RSA is often used to exchange a symmetric key that will be used to encrypt future
messages. It would be terrible, of course, if an adversary were able to learn that key.
And, that’s what we’re about to do. One of textbook RSA’s great weaknesses is its
malleability, i.e. an active attacker can change the meaning of the plaintext message
by performing an operation on the respective ciphertext. To demonstrate the dangers
of malleability, implement the following protocol
"""

GLOBAL_E = 65537

# https://en.wikipedia.org/wiki/RSA_cryptosystem
"""
Key generation
The keys for the RSA algorithm are generated in the following way:

Choose two large prime numbers p and q.
To make factoring infeasible, p and q must be chosen at random from a large space of possibilities, such as all prime numbers between 21023 and 21024 (corresponding to a 2,048-bit key). Many different algorithms for prime selection are used in practice.[29]
p and q are kept secret.
Compute n = pq.
n is used as the modulus for both the public and private keys. Its length, usually expressed in bits, is the key length.
n is released as part of the public key.
Compute λ(n), where λ is Carmichael's totient function. Since n = pq, λ(n) = lcm(λ(p), λ(q)), and since p and q are prime, λ(p) = φ(p) = p − 1, and likewise λ(q) = q − 1. Hence λ(n) = lcm(p − 1, q − 1).
The lcm may be calculated through the Euclidean algorithm, since lcm(a, b) = ⁠
|ab|
/
gcd(a, b)⁠.
λ(n) is kept secret.
Choose an integer e such that 1 < e < λ(n) and gcd(e, λ(n)) = 1; that is, e and λ(n) are coprime.
e having a short bit-length and small Hamming weight results in more efficient encryption – the most commonly chosen value for e is 216 + 1 = 65537. The smallest (and fastest) possible value for e is 3, but such a small value for e may expose vulnerabilities in insecure padding schemes.[30][a]
e is released as part of the public key.
Determine d as d ≡ e−1 (mod λ(n)); that is, d is the modular multiplicative inverse of e modulo λ(n).
This means: solve for d the equation de ≡ 1 (mod λ(n)); d can be computed efficiently by using the extended Euclidean algorithm, since, thanks to e and λ(n) being coprime, said equation is a form of Bézout's identity, where d is one of the coefficients.
d is kept secret as the private key exponent.
The public key consists of the modulus n and the public exponent e. The private key consists of the private exponent d, which must be kept secret. p, q, and λ(n) must also be kept secret because they can be used to calculate d. In fact, they can all be discarded after d has been computed.[31]
"""


def mod_pow(base: int, exponent: int, modulus: int) -> int:
    """Compute (base^exponent) % modulus efficiently"""
    result = 1
    base = int(base) % int(modulus)
    while exponent > 0:
        if exponent % 2 == 1:
            result = int(result * base) % int(modulus)
        exponent = exponent >> 1
        base = int(base * base) % int(modulus)
    return result


def mod_inverse(a: int, m: int):
    """Compute the modular multiplicative inverse of a modulo m"""

    def egcd(a: int, b: int):
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = egcd(int(b) % int(a), a)
            return (g, x - int(b // a) * y, y)

    g, x, _ = egcd(int(a), int(m))
    if g != 1:
        raise Exception("Modular inverse does not exist")
    else:
        return int(x) % int(m)


def RSA_encrypt(prime1, prime2, m: bytes) -> tuple[bytes, int, int]:
    global GLOBAL_E

    n = prime1 * prime2

    n = prime1 * prime2
    phi = (prime1 - 1) * (prime2 - 1)
    e = 65537
    d = mod_inverse(e, phi)

    # print(f"p = {prime1} and q = {prime2}")
    # print(f"n = {prime1} x {prime2} = {n}")
    # print(f"ϕ({n}) = {prime1 - 1} x {prime2 - 1} = {phi}")
    # print(f"Select e relatively prime to {phi} and e < {phi}; we choose e = {e}")
    # print(f"d = {d} because {d} x {e} mod {phi} = {(d * e) % phi}")

    # Public and Private keys
    PU = (e, n)
    PR = (d, n)

    # print(f"PU = {{{e}, {n}}}")
    # print(f"PR = {{{d}, {n}}}")

    # Encryption
    # m = 88  # plaintext
    C = mod_pow(int.from_bytes(m), e, n)
    # print(f"\nSelect plaintext M = {M}")
    # print(f"Ciphertext C = {M}^{e} mod {n} = {C}")

    return C.to_bytes((C.bit_length() + 7) // 8, byteorder='big'), d, n


def RSA_decrypt(ciphertext: bytes, d: int, n: int) -> bytes:
    M_decrypted = mod_pow(int.from_bytes(ciphertext, byteorder='big'), d, n)
    return M_decrypted.to_bytes((M_decrypted.bit_length() + 7) // 8, byteorder='big')



def main():
    # Given values

    ##### Part 1 #####
    

    #Your implmentation should support variable length primes up to 2048 bits
    p = Crypto.Math.Primality.generate_probable_prime(exact_bits=2048)
    q = Crypto.Math.Primality.generate_probable_prime(exact_bits=2048)
    message = b"hello"
    CT, d, n = RSA_encrypt(p, q, message)
    print(CT)
    PT = RSA_decrypt(CT, d, n)
    print(PT)

    ###################

    ##### PART 2 #####
    alice_p = Crypto.Math.Primality.generate_probable_prime(exact_bits=2048)
    alice_q = Crypto.Math.Primality.generate_probable_prime(exact_bits=2048)
    alice_n = alice_p * alice_q
    #Note: GLOBAL_E = 65537

    bob_s = random.randrange(2, alice_n)
    bob_c = mod_pow(bob_s, GLOBAL_E, alice_n)

    # Find a value for c’ that Mallory will substitute for the ciphertext c that will allow 
    # Mallory to decrypt the ciphertext c0 and recover m. Hint: Mallory knows Alice’s
    # public key (n,e) and can send a value of c’ to Alice that will allow Mallory to know 
    # the value of s without knowing Alice’s private key.

    # Mallory's attack: c' =  c * t^e mod n
    mallory_t = 20
    mallory_c_prime = (int(bob_c) * int(mod_pow(mallory_t, GLOBAL_E, alice_n))) % int(alice_n)

    # Mallory sends c' to Alice
    # https://en.wikipedia.org/wiki/Malleability_%28cryptography%29 

    alice_phi = (alice_p - 1) * (alice_q - 1)
    alice_d = mod_inverse(GLOBAL_E, alice_phi)
    alice_s = mod_pow(mallory_c_prime, alice_d, alice_n)

    mallory_s = int(bob_s * mallory_t) % int(alice_n)
    #mallory_s = mod_pow(mallory_c_prime, mallory_d, alice_n)

    print(
        f" Verify same s values from Alice and Mallory [Alice, Mallory]: {alice_s} == {mallory_s} ? {alice_s == mallory_s}"
    )

    #k = SHA256(s)
    alice_k = SHA256.new()
    alice_k.update(alice_s.to_bytes((int(alice_n).bit_length() + 7) // 8, byteorder='big'))
    alice_k_bytes = alice_k.digest()
    trunc_alice_k = bytearray(alice_k_bytes)[:16]

    # Mallory knows alice's s value
    mallory_k = SHA256.new()
    mallory_k.update(mallory_s.to_bytes((int(alice_n).bit_length() + 7) // 8, byteorder='big'))
    mallory_k_bytes = mallory_k.digest()
    trunc_mallory_k = bytearray(mallory_k_bytes)[:16]
    # Alice attempts to send a message to Bob
    message_from_alice = b"Hello Bob"

    # encrypt
    cipher_encrypt_alice = AES.new(trunc_alice_k, AES.MODE_CBC, GLOBAL_IV)
    ciphertext_from_alice = cipher_encrypt_alice.encrypt(
        pad(message_from_alice, AES.block_size)
    )

    print("keys equal:", trunc_alice_k == trunc_mallory_k)
    print("iv length:", len(GLOBAL_IV))

    cipher_decrypt_mallory_from_alice = AES.new(trunc_mallory_k, AES.MODE_CBC, GLOBAL_IV)
    plaintext_intercepted_by_mallory_from_alice = unpad(
        cipher_decrypt_mallory_from_alice.decrypt(ciphertext_from_alice),
        AES.block_size,
    )

    print(
        f"""
Mallory intercepted Alice's message: {plaintext_intercepted_by_mallory_from_alice}
    Verify that message Alice sent is the same as the intercepted one [Alice, Mallory]: {message_from_alice} == {plaintext_intercepted_by_mallory_from_alice} ? {message_from_alice == plaintext_intercepted_by_mallory_from_alice}""")

    ##### SIGNATURES #####
    # sign(m,d) = m^d mod n
    message_from_alice = b"Hello Bob"
    message_from_bob = b"Hello Alice"

    bob_p = Crypto.Math.Primality.generate_probable_prime(exact_bits=2048)
    bob_q = Crypto.Math.Primality.generate_probable_prime(exact_bits=2048)
    bob_n = bob_p * bob_q
    bob_phi = (bob_p - 1) * (bob_q - 1)
    bob_d = mod_inverse(GLOBAL_E, bob_phi)

    sign_m1 = mod_pow(message_from_alice, alice_d, alice_n)
    sign_m2 = mod_pow(message_from_bob, bob_d, bob_n)
    
    print(f"Message signature for m1: {sign_m1}")
    print(f"Message signature for m2: {sign_m2}")
    

if __name__ == "__main__":
    main()
