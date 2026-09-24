from Crypto.PublicKey import RSA
from math import gcd

key = RSA.generate(2048)
n = key.n
phi = (key.p - 1) * (key.q - 1)

e_B = key.e
d_B = key.d

e_A = 3
while gcd(e_A, phi) != 1:
    e_A += 2

print(f"n   = {n}")
print(f"e_B = {e_B}")
print(f"d_B = {d_B}")
print(f"e_A = {e_A}")
