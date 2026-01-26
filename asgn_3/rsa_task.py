import Crypto.Math.Primality

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
    base = base % modulus
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus
    return result


def mod_inverse(a: int, m: int):
    """Compute the modular multiplicative inverse of a modulo m"""

    def egcd(a: int, b: int):
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = egcd(b % a, a)
            return (g, x - (b // a) * y, y)

    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception("Modular inverse does not exist")
    else:
        return x % m


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
    C = mod_pow(int(m), e, n)
    # print(f"\nSelect plaintext M = {M}")
    # print(f"Ciphertext C = {M}^{e} mod {n} = {C}")

    return C.to_bytes(), d, n


def RSA_decrypt(ciphertext: bytes, d: int, n: int) -> bytes:
    M_decrypted = mod_pow(int(ciphertext), d, n)
    return M_decrypted.to_bytes()


def main():
    # Given values

    p = Crypto.Math.Primality.generate_probable_prime(exact_bits=2048)
    q = Crypto.Math.Primality.generate_probable_prime(exact_bits=2048)
    message = 12
    CT, d, n = RSA_encrypt(p, q, message.to_bytes())
    print(CT)
    PT = RSA_decrypt(CT, d, n)
    print(PT)


if __name__ == "__main__":
    main()
