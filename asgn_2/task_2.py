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

    # PKCS#7 padding: https://node-security.com/posts/cryptography-pkcs-7-padding/

    bin_val = cipher.decrypt(encrypt)
    # print(bin_val)
    # print(len(bin_val))
    url_val = bin_val.decode("ascii")
    print(url_val)
    val = urllib.parse.unquote(url_val)
    # print(val)
    return val


def main():
    enc, key, iv = submit("mytext")
    decode = verify(enc, key, iv)
    print(decode)
    pass


if __name__ == "__main__":
    main()
