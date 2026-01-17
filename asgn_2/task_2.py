import urllib.parse
from mimetypes import encodings_map
from random import randbytes

import numpy as np
from Crypto.Cipher import AES

import block_ciphers


def submit(text: str) -> tuple[bytes, bytes, bytes]:
    begin = "userid=456;userdata="
    end = ";session-id=31337"
    url_text = urllib.parse.quote(begin + text + end)
    plaintext = url_text.encode()

    key = randbytes(16)
    IV = randbytes(16)
    return block_ciphers.encrypt_cbc(key, plaintext, IV, 10), key, IV


def verify(encrypt: bytes, key: bytes, IV: bytes):
    cipher = AES.new(key, AES.MODE_CBC, IV)
    padding_length = (16 - len(encrypt) % 16) % 16  # 0..15 is the range of this.
    # print(encrypt)

    # PKCS#7 padding: https://node-security.com/posts/cryptography-pkcs-7-padding/
    encrypt += bytes([padding_length]) * padding_length

    url_val = cipher.decrypt(encrypt)
    # print(url_val)
    val = urllib.parse.unquote(url_val)
    print(val)


def main():
    enc, key, iv = submit("")
    decode = verify(enc, key, iv)
    pass


if __name__ == "__main__":
    main()
