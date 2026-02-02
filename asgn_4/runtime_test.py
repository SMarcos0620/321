import time
from datetime import timedelta

import bcrypt

password = b"aaaaaa"

individual_cost: list[tuple[int, timedelta]] = []


for cost in range(8, 14):
    salt = bcrypt.gensalt(rounds=cost)

    t0 = time.perf_counter()
    _ = bcrypt.hashpw(password, salt)
    dt = time.perf_counter() - t0

    individual_cost.append((cost, timedelta(milliseconds=dt)))

print("single word")
for c, dt in individual_cost:
    print(f"cost {c:2d} → {dt}")

print("\nword1")
for c, dt in individual_cost:
    # all word cost:
    print(f"cost {c:2d} → {dt * 236736}")
print("\nword1:word2")
for c, dt in individual_cost:
    # all word1:word2 cost:
    print(f"cost {c:2d} → {dt * (236736**2)}")

print("\nword1:word2:(0-99999)")
for c, dt in individual_cost:
    # all word1:word2:digit cost:
    print(f"cost {c:2d} → {dt * (236736**2) * 100000}")

print("\nword1:word2:word3")
for c, dt in individual_cost:
    # all word1:word2:word3 cost:
    print(f"cost {c:2d} → {dt * (236736**3)}")
