class ECPoint:
    """Точка эллиптической кривой в аффинных координатах."""

    __slots__ = ('x', 'y')

    def __init__(self, x=None, y=None):
        self.x = x
        self.y = y

    @property
    def is_infinity(self) -> bool:
        return self.x is None and self.y is None

    def __eq__(self, other):
        if not isinstance(other, ECPoint):
            return NotImplemented
        return self.x == other.x and self.y == other.y

    def __hash__(self):
        return hash((self.x, self.y))

    def __repr__(self):
        if self.is_infinity:
            return "ECPoint()"
        return f"ECPoint({self.x}, {self.y})"


EC_INF = ECPoint()  # точка на бесконечности


def mod_inv(a: int, m: int) -> int:
    """Обратный элемент a^(-1) mod m (расширенный Евклид)."""
    a %= m
    t, new_t = 0, 1
    r, new_r = m, a
    while new_r != 0:
        q = r // new_r
        t, new_t = new_t, t - q * new_t
        r, new_r = new_r, r - q * new_r
    if r != 1:
        raise ValueError(f"{a} не обратим по модулю {m}")
    if t < 0:
        t += m
    return t


# Для сложения точек 𝑃1 = (𝑥1, 𝑦1) и 𝑃2 = (𝑥2, 𝑦2) через них про-
# водят секущую, которая пересекает кривую в третьей точке 𝑃3 с коор-
# динатами (𝑥3, −𝑦3). Тогда точка (𝑥3, 𝑦3), противоположная к точке 𝑃3,
# по определению является суммой точек 𝑃1 и 𝑃2. Закон сложения опи-
# сывается следующими формулами. Если 𝑃1 = 𝑃2, то координаты точ-
# ки 𝑃3 = 𝑃1 + 𝑃2 = 2𝑃1 равны
# 𝑥3 = 𝜆^2 − 2𝑥1(𝑚𝑜𝑑 𝑝),
# 𝑦3 = 𝜆(𝑥1 − 𝑥3) − 𝑦1(𝑚𝑜𝑑 𝑝),
# где угловой коэффициент равен 𝜆 = (3𝑥1^2 + 𝐴)(2𝑦1)^−1(𝑚𝑜𝑑 𝑝).
# Если 𝑃1 ≠ ±𝑃2, то координаты точки 𝑃3 = 𝑃1 + 𝑃2 равны
# 𝑥3 = 𝜆^2 − 𝑥1 − 𝑥2(𝑚𝑜𝑑 𝑝),
# 𝑦3 = 𝜆(𝑥1 − 𝑥3) − 𝑦1(𝑚𝑜𝑑 𝑝),
# где угловой коэффициент равен 𝜆 = (𝑦2 − 𝑦1)(𝑥2 − 𝑥1)^−1(𝑚𝑜𝑑 𝑝).
def add_points(P: ECPoint, Q: ECPoint, a: int, p: int) -> ECPoint:
    """Сложение точек P + Q на кривой y^2 = x^3 + ax + b над GF(p)."""
    # O + Q = Q
    if P.is_infinity:
        return Q
    # P + O = P
    if Q.is_infinity:
        return P

    # P + (-P) = O
    if P.x == Q.x and (P.y + Q.y) % p == 0:
        return EC_INF

    # вычисление углового коэф-а
    if P == Q:
        # случай 𝜆 = (3x1^2 + A)(2y1)^-1 (mod p)
        if P.y == 0:
            return EC_INF
        num = (3 * P.x * P.x + a) % p  # (3x1^2 + A)
        den = (2 * P.y) % p            # (2y1)^-1
    else:
        # случай 𝜆 = (y2 - y1)(x2 - x1)^-1 (mod p)
        num = (Q.y - P.y) % p  # (y2 - y1)
        den = (Q.x - P.x) % p  # (x2 - x1)

    # 𝜆 = num / den
    lam = (num * mod_inv(den, p)) % p

    # вычисление координат на основе углового коэф-а
    x3 = (lam * lam - P.x - Q.x) % p
    y3 = (lam * (P.x - x3) - P.y) % p
    return ECPoint(x3, y3)


# 1. Если 𝑘 = 0, то результат: 𝑃∞ – бесконечно удаленная точка.
# 2. Представить число 𝑘 в двоичной системе счисления: 𝑘 = (𝑘𝑡−1. . . 𝑘1𝑘0)2.
# 3. Положить 𝑄 ← 𝑃∞.
# 4. Для 𝑖 = 𝑡 − 1, ..., 0 выполнить:
# 4.1. 𝑄 ← 2𝑄 (удвоение точки).
# 4.2. Если 𝑘𝑖 ≠ 0, положить 𝑄 ← 𝑄 + 𝑃 (сложение точек).
# 5. Результат 𝑄.
def scalar_mul(k: int, P: ECPoint, a: int, p: int) -> ECPoint:
    """Бинарное умножение точки P на скаляр k."""
    # 1. Если k = 0 → P∞
    if k == 0:
        return EC_INF

    # 2. Двоичное представление k = (k_{t−1} ... k₁ k₀)₂
    bits = bin(k)[2:]  # строка '1010...' от старшего бита к младшему

    # 3. Q ← P∞
    Q = EC_INF

    # 4. Для i = t−1, ..., 0
    for bit in bits:
        # 4.1. Q ← 2Q
        Q = add_points(Q, Q, a, p)
        # 4.2. Если k_i ≠ 0 → Q ← Q + P
        if bit == '1':
            Q = add_points(Q, P, a, p)

    # 5. Результат Q
    return Q


if __name__ == '__main__':
    p = 57896044630612021680684936114742422271145183870487080309667128995208157569947
    a = 1
    q = 28948022315306010840342468057371211135571302038761442251594012761075345324491
    xP = 43490682822985073571091311123441225129011272278165566160439297012894969619553
    yP = 53273700124912449490307054424387372532482586733448415163119878489682918137700

    P = ECPoint(xP, yP)

    # 1. P на кривой
    b = 19750513962881385028059495396984460236743646692126413053976069443380491067343
    assert (P.y**2 - P.x**3 - a*P.x - b) % p == 0
    print("P на кривой")

    # 2. q * P = O
    assert scalar_mul(q, P, a, p).is_infinity
    print("q * P = O")

    # 3. (q + 1) * P = P
    assert scalar_mul(q + 1, P, a, p) == P
    print("(q + 1) * P = P")

    # 4. 2 * P = P + P
    assert scalar_mul(2, P, a, p) == add_points(P, P, a, p)
    print("2 * P = P + P")

    # 5. 3 * P = P + P + P
    P3 = add_points(add_points(P, P, a, p), P, a, p)
    assert scalar_mul(3, P, a, p) == P3
    print("3 * P = P + P + P")
