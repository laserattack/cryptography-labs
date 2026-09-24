"""
Генерирует N зашифрованных файлов одного сообщения с малым e.
"""
import sys
import os

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '1'))
from enc_dec import encrypt_file


# AES-ключ k — один и тот же (40283ed6...).
# AES-шифртекст — один и тот же (сообщение одно).
# RSA-модули n₀, n₁, n₂ — разные.
# e = 3 — маленькое и одинаковое.
# cᵢ = k³ mod nᵢ — разные, потому что модули разные.
def main():
    if len(sys.argv) != 5:
        print("Использование: python3 hastad_generate.py <msg> <e> <count> <prefix>")
        print("msg    - файл сообщения")
        print("e      - малая экспонента (3, 5)")
        print("count  - число получателей (>= e)")
        print("prefix - префикс имён файлов")
        return

    msg_path = sys.argv[1]
    e = int(sys.argv[2])
    count = int(sys.argv[3])
    prefix = sys.argv[4]

    if count < e:
        print(f"Ошибка: нужно минимум {e} получателей")
        return

    aes_key = get_random_bytes(32)
    print(f"Общий AES-ключ: {aes_key.hex()}")

    for i in range(count):
        key = RSA.generate(2048, e=e)

        enc = f"{prefix}_{i}.enc"
        encrypt_file(msg_path, enc, key.n, key.e, f"user{i}", aes_key)
        print(f"Создан: {enc} (n = {key.n.bit_length()} бит, e = {key.e})")


if __name__ == "__main__":
    main()
