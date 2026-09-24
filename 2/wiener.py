from math import gcd


# для разложения e/n в цепную дробь
def continued_fraction(num, den):
    """Цепная дробь для num/den: [a0; a1, a2, ...]."""
    cf = []
    while den:
        q = num // den
        cf.append(q)
        num, den = den, num - q * den
    return cf


# α = a₀ + 1/(a₁ + 1/(a₂ + 1/(a₃ + ...)))
# Подходящая дробь P_i/Q_i — это то, что получается,
# если оборвать цепную дробь на i-м элементе
# P₀/Q₀ = a₀
# P₁/Q₁ = a₀ + 1/a₁
# P₂/Q₂ = a₀ + 1/(a₁ + 1/a₂)
# ...
def convergents(cf):
    """Подходящие дроби P_i/Q_i для цепной дроби cf."""

    # Начальные условия по методичке:
    # P_{-1}=1, Q_{-1}=0, P_0=0, Q_0=1
    p_prev2, p_prev1 = 0, 1
    q_prev2, q_prev1 = 1, 0

    for a in cf:
        # Рекуррентные формулы подходящих дробей:
        #   P_i = a_i * P_{i-1} + P_{i-2}
        #   Q_i = a_i * Q_{i-1} + Q_{i-2}
        p = a * p_prev1 + p_prev2
        q = a * q_prev1 + q_prev2
        yield p, q
        p_prev2, p_prev1 = p_prev1, p
        q_prev2, q_prev1 = q_prev1, q


def wiener_attack(n, e):
    """Атака Винера. Возвращает d или None."""

    # разложение e,n в цепную дробь
    cf = continued_fraction(e, n)

    # идем по подходящим дробям
    for k, d in convergents(cf):

        if d == 0:
            continue
        if k == 0:
            continue

        # и проверка через расшифрование просто, т.е. берется какое то
        # сообщение, зашифровывается и если далее корректно
        # расшифровалось то все ок

        # проверка: (m^e)^d ≡ m (mod n)
        m = 2
        if pow(pow(m, e, n), d, n) == m % n:
            return d

    return None


def test():
    import random
    from math import gcd, isqrt
    from sympy import nextprime

    # Генерируем p, q
    p = nextprime(random.getrandbits(512))
    q = nextprime(random.getrandbits(512))
    n = p * q
    phi = (p - 1) * (q - 1)

    # Маленькое d, взаимно простое с phi
    d = random.getrandbits(64) | 1   # нечётное, ~64 бита
    while gcd(d, phi) != 1:  # должны быть взаимнопростые иначе e не существует
        d = random.getrandbits(64) | 1

    # e = d^{-1} mod phi
    e = pow(d, -1, phi)

    print(f"n = {n.bit_length()} бит")
    print(f"e = {e.bit_length()} бит")
    print(f"d = {d.bit_length()} бит")

    # граница Винера: d < n^(1/4) / 3
    bound = isqrt(isqrt(n)) // 3
    print(f"граница Винера: d < {bound.bit_length()} бит")
    print(f"применимо: {d < bound}")

    # Атака
    d_found = wiener_attack(n, e)
    print(f"d найден: {d_found == d}")


if __name__ == '__main__':
    test()
