import urllib.parse
from random import randbytes

from Crypto.Cipher import AES

import block_ciphers


def submit(text: str) -> tuple[bytes, bytes, bytes]:
    begin = "userid=456;userdata="
    end = ";session-id=31337"
    url_text = urllib.parse.quote(begin + text + end)
    # print(len(url_text))
    plaintext = url_text.encode()

    key = randbytes(16)
    IV = randbytes(16)
    return block_ciphers.encrypt_cbc(key, plaintext, IV), key, IV


def verify(encrypt: bytes, key: bytes, IV: bytes):
    cipher = AES.new(key, AES.MODE_CBC, IV)
    # print(encrypt)

    bin_val = cipher.decrypt(encrypt)
    # print(bin_val)
    # print(len(bin_val))
    url_val = bin_val.decode("ascii", "ignore")
    print(url_val)
    session_raw = urllib.parse.unquote(url_val)

    # remove PKCS#7 padding: https://node-security.com/posts/cryptography-pkcs-7-padding/
    session_data = session_raw.strip()
    print(session_data)

    return ";admin=true;" in session_data


def main():
    print(len(urllib.parse.quote("userid=456;").encode()))
    print(len(urllib.parse.quote("admin=true;").encode()))
    enc, key, iv = submit("a" * 26)

    block0 = bytearray(enc[0:16])
    # We are going to target block 1.
    block0_original = urllib.parse.quote("userid=456;").encode()
    target = urllib.parse.quote("admin=true;").encode()

    for i in range(
        len(urllib.parse.quote("admin=true;").encode())
    ):  # Only flip the first 11 bytes we care about
        block0[i] ^= block0_original[i] ^ target[i]

    # print(enc)

    enc = bytes(block0) + enc[16:]
    # print(inj)
    print(len(bytes(block0)))
    print(len("`q qgrzf5wR!2"))
    # print(enc)

    admin = verify(enc, key, iv)
    print(admin)
    pass


if __name__ == "__main__":
    main()
