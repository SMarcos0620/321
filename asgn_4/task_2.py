import threading
from queue import Queue

import bcrypt as bc
import nltk
from nltk.corpus import words
import time

# Download words corpus if not already present
try:
    word_list = words.words()
except LookupError:
    nltk.download("words")
    word_list = words.words()

word_list: list[str] = words.words()

lookup = {}


q: Queue[str] = Queue()  # fun fact: python is actually strongly-typable
found = threading.Event()
result = None


def worker():
    global result
    while not q.empty() and not found.is_set():
        try:
            w: str = q.get(timeout=0.5)
            hashed = bc.hashpw(w.encode(), salt.encode())

            # print(f"{hashed.decode()} == {salt}{hash}")
            if hashed.decode() == f"{salt}{hash}":
                result = w
                found.set()
                # print(f"[!] PASSWORD FOUND : {w} [!]")
        except Exception as e:
            print(f"Thread had error: {e}")


def crack():
    with open("save1.txt", "r") as file:
        lines = [line.rstrip() for line in file]
        for line in lines:
            q.put(line)
    for w in word_list:
        if len(w) > 6 and len(w) < 11:
            q.put(w)

    threads: list[threading.Thread] = []
    for i in range(NUM_THREADS):
        t = threading.Thread(target=worker, args=())
        t.daemon = True
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    found.clear()


salt = None
NUM_THREADS = 10

with open("shadow.txt", "r") as file:
    lines = [line.rstrip() for line in file]
    for line in lines:
        t0 = time.monotonic()
        values = line.split("$")
        user, algo, workf, salted_hash = values
        partial_salt = salted_hash[:22]
        hash = salted_hash[22:]

        salt = f"${algo}${workf}${partial_salt}"

        print(f"[*] Cracking password for user: {user}")
        print(f"[*] Algorithm: {algo}, Work factor: {workf}")
        print(f"[*] Testing {len(word_list)} words with {NUM_THREADS} threads...")
        crack()
        q = Queue()
        if result:
            t1 = time.monotonic()
            time_elapsed = t1 - t0
            print(f"\n[+] SUCCESS! Password is: {result}\n")
            with open("save1.txt", "a", encoding="utf-8") as f:
                f.write(f"{result} {time_elapsed}\n")

        else:
            t0 = 0
            t1 = 0
            time_elapsed = 0
            print("\n[-] Password not found in wordlist")
