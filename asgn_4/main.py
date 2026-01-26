from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad

def main():
    print("Hello from asgn-4!")

    ##### TASK 1 #####

    # a) . Write a program that uses SHA256 to hash arbitrary inputs and print 
    # the resulting digests to the screen in hexadecimal format.

    #user_in = input("Enter input: ")
    user_in = "Hello from asgn-4!"
    user_k = SHA256.new()
    user_k.update(user_in.encode())
    user_k_bytes = user_k.digest()

    print(f"Input digest: {user_k_bytes}")

if __name__ == "__main__":
    main()
