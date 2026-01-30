import pprint
import secrets
import string
import sys
import time

import polars
from Crypto.Hash import SHA256

"""
Pseudo Code:

sha256_hash(input_string):
FUNCTION sha256_hash(input_string):
Convert input_string to bytes
Calculate SHA256 hash of the bytes
Return the hash as a hexadecimal string
END FUNCTION

truncate_hash(hash_string, bits):
FUNCTION truncate_hash(hash_string, bits):
Take the first (bits / 4) characters of hash_string
Convert this substring to an integer (base 16)
Create a bitmask of 'bits' number of 1s
Perform bitwise AND between the integer and the bitmask
Return the result
END FUNCTION

hamming_distance(s1, s2):
FUNCTION hamming_distance(s1, s2):
Initialize count to 0
FOR each pair of characters (c1, c2) in (s1, s2):
IF c1 != c2:
Increment count
RETURN count
END FUNCTION

find_hamming_distance_1():
FUNCTION find_hamming_distance_1():
Generate a random string 'base' of 10 ASCII letters
FOR each index i in base:
Create 'modified' by flipping the i-th bit of base
IF hamming_distance(base, modified) == 1:
RETURN base, modified
RETURN None, None
END FUNCTION

find_collision(bits, max_attempts):
FUNCTION find_collision(bits, max_attempts):
Initialize empty dictionary 'seen'
Record start time
FOR attempts from 1 to max_attempts:
Generate random string 's' of 10 ASCII letters
Calculate truncated hash 'h' of 's'
IF h exists in seen:
Calculate end time
RETURN seen[h], s, attempts, elapsed time
ELSE:
Add s to seen with key h
RETURN None, None, max_attempts, elapsed time
END FUNCTION

task_1a():
FUNCTION task_1a():
Print "Task 1a: SHA256 hashes of arbitrary inputs"
FOR each input in ["Hello, World!", "Python", "Cryptography"]:
Calculate SHA256 hash of input
Print input and its hash
END FUNCTION

task_1b():
FUNCTION task_1b():
Print "Task 1b: Strings with Hamming distance of 1"
FOR i from 1 to 3:
Find two strings s1, s2 with Hamming distance 1
Calculate SHA256 hashes h1, h2 of s1, s2
Print s1, s2, h1, h2
END FUNCTION

task_1c():
FUNCTION task_1c():
Print "Task 1c: Finding collisions for truncated hashes"
Initialize empty lists for bits, time, and inputs
FOR bits from 8 to 50, step 2:
Find collision for 'bits' number of bits
IF collision found:
Add result to table
Append ˝, time, and inputs to respective lists
ELSE:
Print timeout message
Print results table
Plot graphs:
1. Digest Size vs Collision Time
2. Digest Size vs Number of Inputs
Save graphs as 'collision_analysis.png'
END FUNCTION

"""


def hamming_dist(str1: str, str2: str) -> int:
    count = 0
    for c1, c2 in zip(str1, str2):
        if c1 != c2:
            count += 1
    return count


def find_collision(bits, max_att) -> tuple[bool, str, str, bytes, int, float]:
    # initialize empty dictionary "seen"
    seen = dict()
    # record start time, t0
    t0 = time.monotonic()
    # FOR attempts from 1 to max_attempts
    for attempt in range(1, max_att):
        # Generate random string 's' for 10 ASCII letters
        s = ""
        ascii_list = []
        for _ in range(10):
            # c is a single ASCII char
            c = secrets.choice(string.ascii_letters.join(string.ascii_uppercase))
            # concatenate the ASCII values together
            s += c

        # Calculate truncated hash 'h' of 's'
        h = SHA256.new()
        h.update(s.encode())
        # truncate hash up to bits
        hash = h.digest()[: (bits // 8)]
        # print(f"string: {s}     hash: {hash}")

        # IF h exists in seen:
        if hash in seen:
            # calculate end time
            time_elapsed = t1 - t0
            # print("LINE 137: Collision detected")
            return True, seen[hash], s, hash, attempt, time_elapsed
        # ELSE, add random string 's' to dict 'seen' with key hash 'h'
        else:
            # t1 = end time
            t1 = time.monotonic()
            seen[hash] = s
        time_elapsed = t1 - t0
        # print(f"seen: {seen}")
    return False, None, None, None, max_att, time_elapsed


def main():
    ##### TASK 1 #####

    # a) . Write a program that uses SHA256 to hash arbitrary inputs and print
    # the resulting digests to the screen in hexadecimal format.

    # user_in = input("Enter input: ")
    # store digests into one hash map
    ham_hash = {}
    print("##### Task 1a: #####")

    str1 = "Hello from asgn-4!"
    print(f"str1: {str1}")
    str1_k = SHA256.new()
    str1_k.update(str1.encode())
    str1_k_bytes = str1_k.digest()
    ham_hash[str1] = str1_k_bytes

    print(f"    str1 digest: {str1_k_bytes}")

    # different by one bit (lowercase h)
    str2 = "hello from asgn-4!"
    print(f"str2: {str2}")
    str2_k = SHA256.new()
    str2_k.update(str2.encode())
    str2_k_bytes = str2_k.digest()
    ham_hash[str2] = str2_k_bytes

    print(f"    str2 digest: {str2_k_bytes}")

    # B) hash two strings (of any length) whose Hamming distance is exactly
    # 1 bit (i.e. differ in only 1 bit). Repeat this a few times

    ham_dist = hamming_dist(str1, str2)
    print(f"Hamming distance: {ham_dist} == 1 ? {ham_dist == 1}")
    # https://www.geeksforgeeks.org/dsa/hamming-distance-two-strings/
    slist = ["abcdefghij", "abcdefghik"]
    print(
        f"""\n##### Task 1b: #####\nhamming dist of 2 strings: {hamming_dist(slist[0], slist[1])}"""
    )
    for s in slist:
        h = SHA256.new()
        h.update(s.encode())
        h_hash = h.digest()

        print(f"""String: {s}\nHash: {h.digest()}""")
        ham_hash[s] = h_hash

    print("\n\nHAMMED AND HASHED VALUES:")
    pprint.pprint(ham_hash)

    # Part C: Modify your program to compute SHA256 hashes of arbitrary inputs, so that it is
    # able to truncate the digests to between 8 and 50 bits

    trunc_bits = 8
    for str, digest in ham_hash.items():
        ham_hash[str] = digest[:trunc_bits]

    print("\n\nHAMMED, HASHED, AND TRUNCATED VALUES:")
    pprint.pprint(ham_hash)

    # TASK c:
    print("\n##### Task 1c: #####")

    max_attempts = sys.maxsize
    # FOR bits from 8 to 50, step 2
    df = polars.DataFrame()

    for i in range(8, 52, 2):
        # collision_tuple: bool, seen, s, attempt, time
        found, s1, s2, hash, attempts, time_elapsed = find_collision(i, max_attempts)
        # print(f"Collision tuple: {collision_tuple}")
        # if collision found:
        #

        if found:
            print(
                f"for {i}-bit hash, there was a collision detected: {(s1, s2, hash, time_elapsed)}"
            )

            row = polars.DataFrame(
                [
                    {
                        "Bit Size": i,
                        "Input 1": s1,
                        "Input 2": s2,
                        "Hash": hash,
                        "Tries": attempts,
                        "Time (s)": time_elapsed,
                    }
                ]
            )

            df = df.vstack(row)

            # print(df["Bit Size"])
            # print(df)
        else:
            print("Collision not detected. Timeout")
            # ik this is not a timeout, but just a placeholder
            exit()
    print(df)


if __name__ == "__main__":
    main()
