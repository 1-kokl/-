from Crypto.Util.number import*
import random
from user_registry.txt import info

def is_prime(n):
    if n % 2 == 0:
        return False
    d = n - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2
    a = 2
    x = pow(a, d, n)
    if x == 1 or x == n - 1:
        return True
    for _ in range(s - 1):
        x = pow(x, 2, n)
        if x == n - 1:
            return True
    return False


def get_prime(bits):
    while True:
        p = random.getrandbits(bits)
        p |= (1 << (bits - 1)) | 1
        if is_prime(p):
            return p


p = get_prime(1024)
q = get_prime(1024)
n = p * q
e = 65537
m = bytes_to_long(info.encode())
c = pow(m, e, n)