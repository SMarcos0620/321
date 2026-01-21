import urllib.parse
from random import randbytes

from Crypto.Cipher import AES

import block_ciphers

GLOBAL_KEY = randbytes(16)
GLOBAL_IV = randbytes(16)


def submit(text: str) -> tuple[bytes, bytes, bytes]:
    """
    Takes an arbitrary string provided by the user
    and encrypts using CBC
     - prepends "userid=456;userdata="
     - appends ";session-id=31337"
    """
    begin = "userid=456;userdata="
    end = ";session-id=31337"
    created_string = begin + text + end
    # print("Created string: " + created_string)

    # (1) URL encode any ';' and '=' characters that appear in the user provided string
    url_text = urllib.parse.quote(created_string)
    # print("Length: ")
    # print(len(url_text))

    plaintext = url_text.encode()

    key = GLOBAL_KEY
    IV = GLOBAL_IV
    # Submit() returns the resulting ciphertext

    return block_ciphers.encrypt_cbc(key, plaintext, IV), key, IV


def verify(encrypt: bytes, key: bytes, IV: bytes):
    cipher = AES.new(key, AES.MODE_CBC, IV)
    # print(encrypt)

    # (1) decrypt the string
    bin_val = cipher.decrypt(encrypt)

    # remove PKCS#7 padding: https://node-security.com/posts/cryptography-pkcs-7-padding/

    bin_val = bin_val[: len(bin_val) - int(bin_val[len(bin_val) - 1])]

    url_val = bin_val.decode("ascii", "replace")
    print("\nurl_val from verify(): " + url_val)
    session_raw = urllib.parse.unquote(url_val)
    session_data = session_raw.strip()

    # (2) parse the string for ';admin=true;' and (3) return true/false
    return ";admin=true;" in session_data


def bit_flip(ciphertext: bytes) -> bytes:
    """
    We know that our input string will be: mmmmmmmXadminXtrue, where we need to
    flip the appropriate bits in prior blocks in order to swap the X's for appropriate symbols
    """
    mut_ciphertext = bytearray(
        ciphertext
    )  # yes i know i could have found a better name but Rust habits die hard

    # targets of user input values encoded as 'X' chars, but as ints this time.
    flips_needed = [
        (33, "X", ";"),
        (39, "X", "="),
    ]

    # NOTE: the whole string to be evaluated is: userid=456;userdata=mmmmmmmXadminXtrue;session-id=31337

    for pos, original, target in flips_needed:
        block_1_pos = pos - 16  # goto the previous block

        mut_ciphertext[block_1_pos] ^= ord(original) ^ ord(target)

    return bytes(mut_ciphertext)


def main():
    # print(len(urllib.parse.quote("userid=456;").encode()))
    # print(len(urllib.parse.quote("admin=true;").encode()))
    user_input = "Here's an example of user input: basic, I know..."
    enc, key, iv = submit(user_input)

    admin = verify(enc, key, iv)
    print("\nverify() returned: ", end="")
    print(str(admin) + "\n")

    # the rest of main is the attack

    # we need to manipulate the input to
    # substitute the bits that
    # will decode down to url syntax
    #
    # we use the 'm' character as a non-url-encoded buffer, and the 'X' character to denote our target.
<<<<<<< HEAD
    
    attack_target = "mmmmmmmXadminXtrue;" + user_input + ''
    enc, key, iv = submit(attack_target)
    
    
=======
    enc, key, iv = submit("mmmmmmmXadminXfalse")
>>>>>>> 2690e9b4a9b79720f550ec681f890778b9076542

    admin = verify(bit_flip(enc), key, iv)
    print("\nverify() returned: ", end="")
    print(str(admin) + "\n")

    pass


if __name__ == "__main__":
    main()
