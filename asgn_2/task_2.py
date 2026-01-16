import urllib.parse
from random import randbytes

import numpy as np

import block_ciphers


def submit(text: str) -> bytes:
    begin = "userid=456;userdata="
    end = ";session-id=31337"
    url_text = urllib.parse.quote(begin + text + end)
    plaintext = url_text.encode()

    plaintext_np = np.frombuffer(plaintext, dtype=np.uint8)

    key = randbytes(16)
    IV = randbytes(16)
    return block_ciphers.encrypt_cbc(key, plaintext_np, IV, 10).tobytes()


def main():
    print(submit("hello"))
    pass


if __name__ == "__main__":
    main()
