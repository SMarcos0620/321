from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
import textdistance

def main():
    ##### TASK 1 #####

    # a) . Write a program that uses SHA256 to hash arbitrary inputs and print 
    # the resulting digests to the screen in hexadecimal format.

    #user_in = input("Enter input: ")
    
    str1 = "Hello from asgn-4!"
    print(f"str1: {str1}")
    str1_k = SHA256.new()
    str1_k.update(str1.encode())
    str1_k_bytes = str1_k.digest()

    print(f"    str1 digest: {str1_k_bytes}")

    #different by one bit (lowercase h)
    str2 = "hello from asgn-4!"
    print(f"str2: {str2}")
    str2_k = SHA256.new()
    str2_k.update(str2.encode())
    str2_k_bytes = str2_k.digest()

    print(f"    str2 digest: {str2_k_bytes}")

    # B) hash two strings (of any length) whose Hamming distance is exactly 
    # 1 bit (i.e. differ in only 1 bit). Repeat this a few times

    ham_dist = textdistance.hamming.distance(str1, str2)
    print(f"Hamming distance: {ham_dist} == 1 ? {ham_dist == 1}")
    #https://www.geeksforgeeks.org/dsa/hamming-distance-two-strings/
if __name__ == "__main__":
    main()
