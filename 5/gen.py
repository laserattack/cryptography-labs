"""
Сравнение n1 = p²·q  и  n2 = p·q  ОДИНАКОВОЙ длины.
"""

from sympy import nextprime
import random


def gen_p2q(bits=100):
    """n = p² · q, длина ~bits. p маленькое."""
    bits_p = bits // 6                  # ~16 бит при 100
    bits_q = bits - 2 * bits_p          # ~68 бит

    p = nextprime(random.getrandbits(bits_p))
    q = nextprime(random.getrandbits(bits_q))
    return p * p * q, p, q


def gen_pq(bits=100):
    """n = p · q, длина ~bits. Сбалансированные."""
    p = nextprime(random.getrandbits(bits // 2))
    q = nextprime(random.getrandbits(bits // 2))
    return p * q, p, q


if __name__ == '__main__':
    BITS = 100

    n1, p1, q1 = gen_p2q(BITS)
    print("=== n1 = p² · q ===")
    print(f"n1 = {n1}")
    print(f"  знаков: {len(str(n1))}, бит: {n1.bit_length()}")
    print(f"  p = {p1} ({p1.bit_length()} бит)")
    print(f"  q = {q1} ({q1.bit_length()} бит)")
    print()

    n2, p2, q2 = gen_pq(BITS)
    print("=== n2 = p · q ===")
    print(f"n2 = {n2}")
    print(f"  знаков: {len(str(n2))}, бит: {n2.bit_length()}")
    print(f"  p = {p2} ({p2.bit_length()} бит)")
    print(f"  q = {q2} ({q2.bit_length()} бит)")
