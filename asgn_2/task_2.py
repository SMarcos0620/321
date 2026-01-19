import urllib.parse
from random import randbytes

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

import block_ciphers

'''
Takes an arbitrary string provided by the user
 - prepends "userid=456;userdata="
 - appends ";session-id=31337"
'''
def submit(text: str) -> tuple[bytes, bytes, bytes]:
    begin = "userid=456;userdata="
    end = ";session-id=31337"
    created_string = begin + text + end
    #print("Created string: " + created_string)
    
    #(1) URL encode any ';' and '=' characters that appear in the user provided string
    url_text = urllib.parse.quote(created_string)
    #print("Length: ")
    #print(len(url_text))

    #(2) pad the final string (using PKCS#7)
    #https://pycryptodome.readthedocs.io/en/latest/src/util/util.html
    plaintext = url_text.encode()
    url_text = pad(plaintext, 16, style='pkcs7')

    #(3) encrypt the padded string using AES-128-CBC from task 1

    key = randbytes(16)
    IV = randbytes(16)
    #Submit() returns the resulting ciphertext

    return block_ciphers.encrypt_cbc(key, plaintext, IV), key, IV


def verify(encrypt: bytes, key: bytes, IV: bytes):
    cipher = AES.new(key, AES.MODE_CBC, IV)
    # print(encrypt)

    #(1) decrypt the string
    bin_val = cipher.decrypt(encrypt)

    #remove PKCS#7 padding: https://node-security.com/posts/cryptography-pkcs-7-padding/
    #strip() removes all leading and trailing whitespace, i don't think this works to remove pkcs padding
    #https://www.geeksforgeeks.org/python/python-string-strip/ 
    #session_data = session_raw.strip()
    session_data = unpad(bin_val, 16, style='pkcs7')
    print("\nno PKCS#7 padding: ", end='')
    print(session_data)

    # print(bin_val)
    # print(len(bin_val))
    url_val = bin_val.decode("ascii", "ignore")
    print("\nurl_val from verify(): " + url_val)
    session_data = urllib.parse.unquote(url_val)

    

    #(2) parse the string for ';admin=true;' and (3) return true/false
    return ";admin=true;" in session_data


def main():
    print(len(urllib.parse.quote("userid=456;").encode()))
    print(len(urllib.parse.quote("admin=true;").encode()))
    user_input = input("Enter text: ")
    enc, key, iv = submit(user_input * 26)

    admin = verify(enc, key, iv)
    print("\nverify() returned: ", end="")
    print(admin)

    #the rest of main is the attack
    '''
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
    print("\nverify() returned: ", end="")
    print(admin)
    '''
    pass


if __name__ == "__main__":
    main()
