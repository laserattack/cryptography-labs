"""
Генерация параметров Диффи–Хеллмана:
  p — безопасное простое (p = 2q + 1)
  a — образующая подгруппы порядка q (публичное число)
"""

import random
from sympy import isprime


def generate_safe_prime(bits: int = 512):
    """
    Генерирует безопасное простое p = 2q + 1, где q — простое.
    Возвращает (p, q).
    """
    while True:
        q = random.getrandbits(bits - 1)
        q |= (1 << (bits - 2)) | 1
        if not isprime(q):
            continue

        p = 2 * q + 1
        if isprime(p):
            return p, q


def generate_generator(p: int, q: int):
    """
    Находит образующую a подгруппы порядка q в (Z/pZ)*.
    a = h^2 mod p для случайного h.
    """
    while True:
        h = random.randint(2, p - 2)
        a = pow(h, 2, p)
        if a != 1:
            return a


def generate_secret(q: int) -> int:
    """Случайный секрет x (или y) из [2, q-1]."""
    return random.randint(2, q - 1)


def compute_public(a: int, secret: int, p: int) -> int:
    """Публичное значение: a^secret mod p."""
    return pow(a, secret, p)


def compute_shared(other_public: int, my_secret: int, p: int) -> int:
    """Общий секрет: other_public^my_secret mod p."""
    return pow(other_public, my_secret, p)


if __name__ == '__main__':
    # В протоколе Диффи–Хеллмана используется конечная циклическая
    # группа (ℤ/pℤ)*, где p — безопасное простое (p = 2q + 1, q —
    # простое). Число a — образующая подгруппы простого порядка
    # q. Участник A выбирает секрет x, вычисляет A = a^x mod p и
    # отправляет B. Участник B выбирает секрет y, вычисляет B = a^y
    # mod p и отправляет A. Оба получают общий ключ K = a^(xy) mod p.

    p, q = generate_safe_prime(512)
    a = generate_generator(p, q)

    print(f"p = {p}")
    print(f"q = {q}")
    print(f"a = {a}")

    # Проверки параметров
    assert isprime(p)
    assert isprime(q)
    assert p == 2 * q + 1
    assert pow(a, q, p) == 1
    assert a != 1
    print("Параметры корректны")

    # Протокол: A (Алиса) и B (Боб)
    x = generate_secret(q)
    y = generate_secret(q)

    A = compute_public(a, x, p)   # Участник A выбирает секрет x, вычисляет A = a^x mod p
    B = compute_public(a, y, p)   #  Участник B выбирает секрет y, вычисляет B = a^y mod p и отправляет A.

    print(f"x = {x}")
    print(f"y = {y}")
    print(f"A = a^x = {A}")
    print(f"B = a^y = {B}")

    # Общий секрет
    K_alice = compute_shared(B, x, p)   # (a^y)^x = a^(xy)
    K_bob   = compute_shared(A, y, p)   # (a^x)^y = a^(xy)

    print(f"K_Alice = {K_alice}")
    print(f"K_Bob   = {K_bob}")

    assert K_alice == K_bob
    print("Общий секрет совпадает")
