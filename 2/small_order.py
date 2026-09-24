import sys


def small_order_attack(n: int, e: int, c: int) -> tuple[int, int]:
    """Атака на малый порядок e. Возвращает (m, число_итераций)."""
    c0 = c
    c_prev = c0
    i = 1

    while True:
        ci = pow(c_prev, e, n)
        if ci == c0:
            return c_prev, i
        c_prev = ci
        i += 1


# python3 small_order.py 77 13 5
def main():
    if len(sys.argv) != 4:
        print("Использование: python3 small_order.py <n> <e> <c>")
        return

    n = int(sys.argv[1])
    e = int(sys.argv[2])
    c = int(sys.argv[3])

    if not (0 <= c < n):
        print("Ошибка: c должно быть в [0, n)")
        return

    m, iters = small_order_attack(n, e, c)

    print(f"n = {n}")
    print(f"e = {e}")
    print(f"c = {c}")
    print(f"m = {m}")
    print(f"итераций: {iters}")

    if pow(m, e, n) == c:
        print("Проверка пройдена: m^e mod n == c")
    else:
        print("Ошибка: m^e mod n != c")


if __name__ == "__main__":
    main()
