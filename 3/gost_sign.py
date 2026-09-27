from gostcrypto import gosthash
import random

from ec_math import ECPoint, EC_INF, add_points, scalar_mul, mod_inv

# Параметры кривой (из parameters.md)
p = 57896044630612021680684936114742422271145183870487080309667128995208157569947
q = 28948022315306010840342468057371211135571302038761442251594012761075345324491
a = 1
b = 19750513962881385028059495396984460236743646692126413053976069443380491067343
xP = 43490682822985073571091311123441225129011272278165566160439297012894969619553
yP = 53273700124912449490307054424387372532482586733448415163119878489682918137700

P = ECPoint(xP, yP)


def hash_message(message: bytes) -> int:
    """
    Хеш сообщения по ГОСТ Р 34.11-2012 (Стрибог-256),
    приведённый по модулю q с заменой нуля на единицу.

    Параметры:
      message — байты сообщения

    Возвращает:
      e ∈ [1, q-1]
    """
    # # Вычисляет хэш-образ сообщения 𝑀: ℎ̄ ← ℎ(𝑀).
    h = gosthash.GOST34112012('streebog256', bytearray(message))
    digest = h.digest()

    # Вычисляет число 𝛼 ∈ ℤ, двоичным представлением которого является вектор ℎ̄
    a = int.from_bytes(digest, byteorder='big')

    # Находит 𝑒 ≡ 𝛼(𝑚𝑜𝑑 𝑞)
    e = a % q

    # при 𝑒 = 0 полагает 𝑒 ← 1.
    if e == 0:
        e = 1

    return e


def generate_keypair():
    """
    Генерация ключевой пары по ГОСТ Р 34.10-2018.

    Возвращает:
      d — секретный ключ (целое из [1, q-1])
      Q — открытый ключ (точка Q = d·P)
    """
    d = random.randint(1, q - 1)
    Q = scalar_mul(d, P, a, p)
    return d, Q


# 1. h̄ = h(M)
# 2. α = int(h̄), e = α mod q, если e = 0 → e = 1
# 3. k ∈ [1, q−1] случайное
# 4. C = kP, r = C.x mod q, если r = 0 → на шаг 3
# 5. s = (r·d + k·e) mod q, если s = 0 → на шаг 3
# 6. Подпись: (r, s)
def sign(message: bytes, d: int) -> tuple[int, int]:
    """
    Формирование подписи по ГОСТ Р 34.10-2018.

    Параметры:
      message — байты сообщения
      d       — закрытый ключ

    Возвращает:
      (r, s) — подпись
    """
    # 1-2. хэш и приведение mod q
    e = hash_message(message)

    # 3-5. цикл: пока r или s не равны нулю
    while True:
        # 3. случайный k
        k = random.randint(1, q - 1)

        # 4. C = kP, r = C.x mod q
        C = scalar_mul(k, P, a, p)
        r = C.x % q
        if r == 0:
            continue

        # 5. s = (r·d + k·e) mod q
        s = (r * d + k * e) % q
        if s == 0:
            continue

        # 6. подпись
        return r, s


# 1. Проверить: 0 < r < q и 0 < s < q
# 2. e = h(M) mod q    (если e = 0 → e = 1)
# 3. v = e^(-1) mod q
# 4. z1 = (s · v) mod q
# 5. z2 = (−r · v) mod q
# 6. C = z1·P + z2·Q
# 7. R = C.x mod q
# 8. Подпись верна ⟺ R == r
def verify(message: bytes, r: int, s: int, Q: ECPoint) -> bool:
    """
    Проверка подписи по ГОСТ Р 34.10-2018.

    Параметры:
      message — байты сообщения
      r, s    — подпись
      Q       — открытый ключ

    Возвращает:
      True, если подпись верна, иначе False
    """
    # 1. Проверка диапазонов
    if not (0 < r < q and 0 < s < q):
        return False

    # 2. хэш
    e = hash_message(message)

    # 3. v = e^(-1) mod q
    v = mod_inv(e, q)

    # 4. z1 = s·v mod q
    z1 = (s * v) % q

    # 5. z2 = −r·v mod q
    z2 = (-r * v) % q

    # 6. C = z1·P + z2·Q
    C = add_points(
        scalar_mul(z1, P, a, p),
        scalar_mul(z2, Q, a, p),
        a, p
    )

    # 7. R = C.x mod q
    if C.is_infinity:
        return False
    R = C.x % q

    # 8. сравнение
    return R == r


if __name__ == '__main__':
    d, Q = generate_keypair()
    msg = b"test message"

    r, s = sign(msg, d)

    # 1. Правильная подпись
    assert verify(msg, r, s, Q) is True

    # 2. Изменённое сообщение
    assert verify(b"other message", r, s, Q) is False

    # 3. Изменённая подпись
    assert verify(msg, r + 1, s, Q) is False

    # 4. Подпись другого ключа
    d2, Q2 = generate_keypair()
    assert verify(msg, r, s, Q2) is False

    print("успех")
