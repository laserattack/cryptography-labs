"""
Алгоритм Ленстры — факторизация n
через эллиптические кривые над ℤ/nℤ.

Использование:
    python3 ecm.py <n> [m] [max_curves]
"""

import math
import random
import sys
import time
from math import gcd


#  Точка ЭК в аффинных координатах


class Point:
    """Точка ЭК. Точка на бесконечности — с x=None, y=None."""
    __slots__ = ('x', 'y')

    def __init__(self, x=None, y=None):
        self.x = x
        self.y = y

    @property
    def is_infinity(self):
        return self.x is None

    def __eq__(self, other):
        if not isinstance(other, Point):
            return NotImplemented
        return self.x == other.x and self.y == other.y

    def __repr__(self):
        if self.is_infinity:
            return "Point(∞)"
        return f"Point({self.x}, {self.y})"


O = Point()   # точка на бесконечности


#  Исключение при нахождении делителя


class FactorFound(Exception):
    """Сигнал: найден нетривиальный делитель n."""
    def __init__(self, d):
        self.d = d
        super().__init__(f"Найден делитель: {d}")


#  Сложение точек mod n с проверкой gcd(λ₁, n)


def add_points(P, Q, a, n):
    """
    Сложение P + Q на кривой y² = x³ + ax + b mod n.

    При каждом вычислении знаменателя λ₁:
      d = gcd(λ₁, n)
      - если 1 < d < n → возбуждаем FactorFound(d)
      - если d = n     → λ₁ ≡ 0 mod n, вырождение в обеих
                          компонентах → возвращаем O
      - если d = 1     → всё ок, продолжаем
    """
    if P.is_infinity:
        return Q
    if Q.is_infinity:
        return P

    # P + (−P) = O
    if P.x == Q.x and (P.y + Q.y) % n == 0:
        return O

    # λ = num / λ₁ mod n
    if P.x == Q.x and P.y == Q.y:
        # удвоение: λ = (3x² + a) / (2y)
        if P.y == 0:
            return O
        num = (3 * P.x * P.x + a) % n
        lam1 = (2 * P.y) % n
    else:
        # сложение: λ = (y₂ − y₁) / (x₂ − x₁)
        num = (Q.y - P.y) % n
        lam1 = (Q.x - P.x) % n

    # проверка gcd(λ₁, n)
    d = gcd(lam1, n)
    if 1 < d < n:
        raise FactorFound(d)
    if d == n:
        return O

    lam = (num * pow(lam1, -1, n)) % n
    x3 = (lam * lam - P.x - Q.x) % n
    y3 = (lam * (P.x - x3) - P.y) % n
    return Point(x3, y3)


#  Умножение k · P


def mul_point(k, P, a, n):
    """k · P. При каждом сложении проверяется gcd(λ₁, n)."""
    result = O
    addend = P
    while k > 0:
        if k & 1:
            result = add_points(result, addend, a, n)
        addend = add_points(addend, addend, a, n)
        k >>= 1
    return result


#  Случайная кривая + точка


def random_curve(n):
    """
    Возвращает (a, Q) — коэффициент a и точку Q на кривой
    y² = x³ + ax + b mod n.

    Сначала выбираем x0, y0, a; затем b = y0² − x0³ − a·x0 mod n.
    Проверяем, что кривая неособая: gcd(4a³ + 27b², n) = 1.
    """
    x0 = random.randrange(1, n)
    y0 = random.randrange(1, n)
    a = random.randrange(0, n)

    b = (y0 * y0 - x0 * x0 * x0 - a * x0) % n
    disc = (4 * pow(a, 3, n) + 27 * pow(b, 2, n)) % n

    d = gcd(disc, n)
    if d != 1:
        # особая кривая — берём другую
        return None

    return a, Point(x0, y0)


#  База простых < m (решето Эратосфена)


def primes_up_to(m):
    """Список простых чисел < m."""
    if m < 3:
        return []
    sieve = bytearray([1]) * m
    sieve[0] = sieve[1] = 0
    for i in range(2, int(m ** 0.5) + 1):
        if sieve[i]:
            sieve[i * i::i] = b'\x00' * len(sieve[i * i::i])
    return [i for i, v in enumerate(sieve) if v]


#  Формат времени


def fmt_time(sec):
    if sec < 60:
        return f"{sec:.2f}с"
    m, s = divmod(sec, 60)
    return f"{int(m)}м {s:.1f}с"


#  Алгоритм


def ecm_factor(n, m=10_000, max_curves=100, verbose=True,
               report_every=5.0):
    """
    Факторизация n методом ECM (алгоритм 8.1).

    n             — составное число
    m             — граница гладкости (размер базы D)
    max_curves    — максимум попыток разных кривых
    verbose       — печатать прогресс
    report_every  — интервал прогресса в секундах

    Возвращает (делитель d или None, время работы, число умножений).
    """
    t_start = time.perf_counter()

    # быстрые проверки
    if n % 2 == 0:
        return 2, time.perf_counter() - t_start, 0
    if n < 4:
        return None, time.perf_counter() - t_start, 0

    D = primes_up_to(m)
    if verbose:
        print(f"[*] База D: {len(D)} простых < {m}")

    # для прогресса по времени
    t_last_report = t_start
    total_mul = 0

    for attempt in range(1, max_curves + 1):
        if verbose:
            print(f"[Кривая {attempt}/{max_curves}]")

        # Шаг 1: случайная кривая и точка Q
        res = random_curve(n)
        if res is None:
            continue

        a, Q = res

        # Шаг 2: Q_i ← Q
        Q_cur = Q

        try:
            # Шаг 3: обход простых p_i ∈ D
            for i, p_i in enumerate(D, start=1):
                # Шаг 4: α_i = ⌊0.5 · ln n / ln p_i⌋
                alpha_i = int(0.5 * math.log(n) / math.log(p_i))

                # Шаг 5: j = 0, 1, ..., α_i − 1
                for _ in range(alpha_i):
                    # Шаг 5.1: Q_i ← p_i · Q_i
                    Q_cur = mul_point(p_i, Q_cur, a, n)
                    total_mul += 1

                    # прогресс по времени
                    if verbose:
                        t_now = time.perf_counter()
                        if t_now - t_last_report >= report_every:
                            elapsed = t_now - t_start
                            print(f"    прошло {fmt_time(elapsed)}, "
                                  f"кривая {attempt}/{max_curves}, "
                                  f"p={p_i}, "
                                  f"умножений: {total_mul}")
                            t_last_report = t_now

        except FactorFound as e:
            return e.d, time.perf_counter() - t_start, total_mul

        # Шаг 6: если делитель не найден — следующая кривая

    return None, time.perf_counter() - t_start, total_mul


#  CLI


def main():
    if len(sys.argv) < 2:
        print("Использование: python3 ecm.py <n> [m] [max_curves]")
        print("n — составное число")
        print("m — граница гладкости (по умолчанию 10^4)")
        print("max_curves — максимум кривых (по умолчанию 100)")
        return

    n = int(sys.argv[1])
    m = int(sys.argv[2]) if len(sys.argv) > 2 else 10_000
    max_curves = int(sys.argv[3]) if len(sys.argv) > 3 else 100

    print(f"[*] n = {n}")
    print(f"[*] m = {m}")
    print(f"[*] max_curves = {max_curves}")

    d, elapsed, total_mul = ecm_factor(n, m=m, max_curves=max_curves, verbose=True, report_every=300.0)

    if d is None:
        print("[!] Делитель не найден")
        print(f"[!] Время: {fmt_time(elapsed)}")
        print(f"[!] Умножений: {total_mul}")
        return

    print(f"[+] Делитель: {d}")
    print(f"[+] Второй множитель: {n // d}")
    print(f"[+] Время: {fmt_time(elapsed)}")
    print(f"[+] Умножений: {total_mul}")
    print(f"[+] Знаков в n: {len(str(n))}")
    print(f"[+] Знаков в делителе: {len(str(d))}")
    print(f"[+] Знаков во втором множителе: {len(str(n // d))}")
    assert n % d == 0
    assert n % d == 0


# python3 ecm.py 1191515026104746183243378937330489098579 1000000 1000
# python3 ecm.py 661643 1000 100
if __name__ == '__main__':
    main()
