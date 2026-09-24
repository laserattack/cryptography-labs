from Crypto.Util.number import getPrime
from math import gcd


def gen_wiener_key(bits_n=1024, bits_d=64):
    """Генерирует уязвимый к Винеру ключ: маленькое d."""
    while True:
        p = getPrime(bits_n // 2)
        q = getPrime(bits_n // 2)

        if p == q:
            continue

        n = p * q
        phi = (p - 1) * (q - 1)

        # маленькое d, взаимно простое с phi
        d = 0
        while d == 0 or gcd(d, phi) != 1:
            d = int.from_bytes(__import__("os").urandom(bits_d // 8), "big") | 1

        # проверка границы Винера: d < n^(1/4) / 3
        from math import isqrt
        if d >= isqrt(isqrt(n)) // 3:
            continue

        # e = d^{-1} mod phi
        e = pow(d, -1, phi)

        return n, e, d


if __name__ == "__main__":
    import sys

    bits_n = int(sys.argv[1]) if len(sys.argv) > 1 else 1024
    bits_d = int(sys.argv[2]) if len(sys.argv) > 2 else 64

    n, e, d = gen_wiener_key(bits_n, bits_d)

    print(f"n = {n}")
    print(f"e = {e}")
