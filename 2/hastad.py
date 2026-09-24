"""
Атака Хастада на широковещательное сообщение.

Дано:
  N зашифрованных файлов (от разных получателей) одного AES-ключа k.
  Все с одним малым e (например, e = 3).

Нужно:
  восстановить k и расшифровать сообщение.

Логика:
  c_i = k^e mod n_i
  По CRT: M = k^e mod (n_1 * n_2 * ... * n_e)
  Так как k < n_i, то M = k^e (без модуля)
  k = целочисленный корень e-й степени из M
"""

import os
import sys
from math import gcd, isqrt

from pyasn1.codec.der import decoder
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '1'))

from asn1_types import EncryptedFileHeader

def crt(remainders, moduli):
    """Китайская теорема об остатках."""
    N = 1
    for n in moduli:
        N *= n

    result = 0
    for c, n in zip(remainders, moduli):
        Ni = N // n
        inv = pow(Ni, -1, n)
        result += c * Ni * inv

    return result % N


def integer_nth_root(x: int, n: int) -> int:
    """Целочисленный корень n-й степени из x (floor)."""
    if x < 0:
        raise ValueError("x must be non-negative")
    if x == 0:
        return 0

    # начальное приближение
    lo, hi = 0, 1
    while hi ** n <= x:
        hi *= 2

    # бинарный поиск
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if mid ** n <= x:
            lo = mid
        else:
            hi = mid

    return lo


def parse_encrypted_file(path: str):
    """Читает файл и возвращает (n, e, c, iv, ciphertext, file_len)."""
    with open(path, 'rb') as f:
        data = f.read()

    header, remaining = decoder.decode(data, asn1Spec=EncryptedFileHeader())

    key_info = header['keys'].getComponentByPosition(0)
    n = int(key_info['publicKey']['modulus'])
    e = int(key_info['publicKey']['publicExponent'])
    c = int(key_info['ciphertext']['ciphertext'])
    file_len = int(header['fileInfo']['fileLength'])

    iv = remaining[:16]
    ciphertext = remaining[16:]

    return n, e, c, iv, ciphertext, file_len


# - Сообщение m (одинаковое для всех в рассылке)
# - Открытые ключи пользователей: `(e, n1), (e, n2),..., (e, nz)`
#   (открытый показатель у всех одинаковый)
# - Шифртексты широковещательного сообщения: `c1, c2,..., cz`

# ну тут просто вот такие шифрования проходили

# ```
# c1 ≡ m^e (mod n1)
# c2 ≡ m^e (mod n2)
# ...
# cz ≡ m^e (mod nz)
# ```

# это то же самое что и

# ```
# m^e ≡ c1 (mod n1)
# m^e ≡ c2 (mod n2)
# ...
# m^e ≡ cz (mod nz)
# ```

# по КТО находится m^e и извлекаем корень степени e просто

# работает только если **число всех адресатов >= e**

# **т.е. не надо использовать малые открытые показатели если возможна
# широковещательная рассылка**
def hastad_attack(enc_files: list[str]) -> bytes:
    """Восстанавливает AES-ключ и расшифровывает сообщение."""
    parsed = [parse_encrypted_file(p) for p in enc_files]

    n_list = [p[0] for p in parsed]
    e_list = [p[1] for p in parsed]
    c_list = [p[2] for p in parsed]

    e = e_list[0]
    if not all(ei == e for ei in e_list):
        raise ValueError("Все e должны быть одинаковыми")
    if e > 5:
        raise ValueError(f"e = {e} слишком большое для атаки")

    if len(enc_files) < e:
        raise ValueError(f"Нужно минимум {e} шифртекстов, дано {len(enc_files)}")

    for i in range(len(n_list)):
        for j in range(i + 1, len(n_list)):
            if gcd(n_list[i], n_list[j]) != 1:
                raise ValueError(f"НОД(n_{i}, n_{j}) != 1")

    # CRT: M = k^e mod N
    M = crt(c_list[:e], n_list[:e])

    k_int = integer_nth_root(M, e)
    k_bytes = k_int.to_bytes(32, 'big')

    print(f"Восстановленный AES-ключ: {k_bytes.hex()}")

    # расшифрование AES
    n0, e0, c0, iv, ciphertext, file_len = parsed[0]
    cipher = AES.new(k_bytes, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)

    return plaintext[:file_len]


# echo "Секретное широковещательное сообщение для атаки Хастада" > msg.txt
# python3 hastad_generate.py msg.txt 3 3 user
# python3 hastad.py recovered.txt user_0.enc user_1.enc user_2.enc
# sha1sum msg.txt recovered.txt

def main():
    if len(sys.argv) < 3:
        print("Использование: python3 hastad.py <out> <enc1> <enc2> ... <encN>")
        print("out   - выходной расшифрованный файл")
        print("enc_i - зашифрованные файлы от разных получателей")
        return

    out_path = sys.argv[1]
    enc_files = sys.argv[2:]

    try:
        plaintext = hastad_attack(enc_files)
    except Exception as err:
        print(f"Ошибка: {type(err).__name__}: {err}", file=sys.stderr)
        return

    with open(out_path, 'wb') as f:
        f.write(plaintext)

    print(f"Восстановленный текст сохранён: {out_path}")


if __name__ == "__main__":
    main()
