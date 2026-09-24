import sys
from Crypto.Util import number


# расширенный алгоритм евклида
def egcd(a, b):
    r0, r1 = a, b
    x0, y0, x1, y1 = 1, 0, 0, 1
    while r1 != 0:
        q = r0 // r1
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
        r1, r0 = r0 % r1, r1
    return x0, y0, r0


# нахождение обратного по модулю
def modinv(a, m):
    x, y, g = egcd(a, m)
    if g != 1:  # обратного по модулю нет
        return None
    return x % m


# проверка условия уязвимости винера
def check_wiener(d, n):
    left = (3 * d) ** 4
    right = n
    return left < right


# генерация параметров
def gen(bits):

    e=65537  # стандарт. порядок e в (ℤ/φ(n)ℤ)* огромный
    while True:
        p = number.getPrime(bits // 2)
        q = number.getPrime(bits // 2)
        if p == q:
            continue

        n = p * q
        phi = (p - 1) * (q - 1)

        d = modinv(e, phi)
        if d is None:
            continue

        if check_wiener(d, n):
            continue

        break

    return n, e, d


def main():
    if len(sys.argv) != 2:
        print("Использование: python3 generate_params.py <bits>")
        return

    try:
        bits = int(sys.argv[1])
    except ValueError:
        print("Ошибка: <bits> должно быть целым числом")
        return

    if bits < 16 or bits % 2 != 0:
        print("Ошибка: <bits> должно быть чётным и >= 16")
        return

    n, e, d = gen(bits)
    print(f"n = {n}")
    print(f"e = {e}")
    print(f"d = {d}")


if __name__ == "__main__":
    main()
