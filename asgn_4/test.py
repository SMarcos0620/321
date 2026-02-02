import time
from random import randbytes

import Crypto.Hash.SHA256 as SHA256

bits = randbytes(256)

t0 = time.perf_counter_ns()
h = SHA256.new()
h.update(bits)
h.digest()
t1 = time.perf_counter_ns()

dt_ns = t1 - t0
dt_s = dt_ns / 1e9

big_number = 2**128
sec = big_number / dt_s


yrs = sec / 31557600

print(yrs)
