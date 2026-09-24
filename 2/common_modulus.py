import random
from math import gcd


# СУТЬ: знаешь d => можешь факторизовать n
# - по определению `ed ≡ 1 (modφ(n))`. это то же самое что `ed=1+tφ(n)`
#   = `ed-1=tφ(n)`. обозначим `ed-1` как k. вычисляем `k = ed - 1`
# - k представляется в виде `k = 2^s * r`, где r — нечётное (верно для
#   любого целого)
# - Выбирается случайное a, `1 < a < n-1`
# - Строится последовательность: `a^r mod n, a^(2r) mod n, a^(4r) mod n,
#   ..., a^(2^s * r) mod n`
# - Ищется x (элемент последовательности) в этой последовательности,
#   такой что: `x^2 ≡ 1 (mod n)`, но `x != 1` и `x != n-1`
# - Если такой x найден, то: `p = gcd(x - 1, n)`, `q = gcd(x + 1, n)`
def factorize(n, e_B, d_B, max_attempts=100):
    # k = ed - 1 = t * phi(n)
    k = e_B * d_B - 1

    # k = 2^f * s, где s - нечётное
    f, s = 0, k
    while s % 2 == 0:
        s //= 2
        f += 1

    for _ in range(max_attempts):

        # случайное a, 1 < a < n-1
        a = random.randrange(2, n - 1)

        # первый элемент последовательности: a^s mod n
        b = pow(a, s, n)
        if b == 1:
            continue

        # строим последовательность a^s, a^(2s), a^(4s), ..., a^(2^f * s) mod n
        # ищем x: x^2 ≡ 1 (mod n), x != 1, x != n-1
        t = None
        prev = b
        for _ in range(f):
            cur = pow(prev, 2, n)
            if cur == 1:
                if prev != 1 and prev != n - 1:
                    t = prev
                break
            prev = cur

        if t is None:
            continue

        # p = gcd(x - 1, n), q = gcd(x + 1, n)
        p = gcd(t + 1, n)
        q = gcd(t - 1, n)

        # проверка что нетривальные
        if p in (1, n) or q in (1, n):
            continue

        return p, q
    return None


# получение d при известных e,p,q
def recover_d(e_A, p, q):
    phi = (p - 1) * (q - 1)
    # d * e = 1 mod phi(n)   =>   d = e ^ (-1) mod phi(n)
    return pow(e_A, -1, phi)


def attack(n, e_B, d_B, e_A):
    # получение p,q при известных n,e,d
    res = factorize(n, e_B, d_B)
    if res == None:
        return None
    p, q = res

    # получение закрытого ключа другого пользователя
    # зная p,q
    d_A = recover_d(e_A, p, q)
    return p, q, d_A


def test():
    from Crypto.PublicKey import RSA

    key_B = RSA.generate(1024)
    n, e_B, d_B = key_B.n, key_B.e, key_B.d  # n общий и d,e первого пользователя
    phi = (key_B.p - 1) * (key_B.q - 1)      # общее

    # e должно быть взаимнопростое с phi чтобы был обратный элемент d
    e_A = 3
    while gcd(e_A, phi) != 1:
        # для RSA p,q нечетные, значит phi четное, значит четные точно
        # не взаимнопростые, поэтому прибавляется 2
        e_A += 2

    # d * e = 1 mod phi(n)   =>   d = e ^ (-1) mod phi(n)
    d_A_real = pow(e_A, -1, phi)  # закрытый ключ второго пользователя

    result = attack(n, e_B, d_B, e_A)
    if result is None:
        print("fail")
        return

    p, q, d_A = result
    print("d_A correct:", d_A == d_A_real)


if __name__ == '__main__':
    test()
