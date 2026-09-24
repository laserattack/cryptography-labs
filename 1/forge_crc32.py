"""
П-3: атака на CRC32-подпись.

Дано:
  Д-1  — исходный документ (для целевого CRC32)
  Д-2  — изменённый документ
  ЭП-1 — подпись для Д-1 (не используется напрямую, только для проверки)

Нужно:
  Д-3 = Д-2 || pad,  CRC32(Д-3) == CRC32(Д-1)

Логика:
  CRC32 — обратимая функция. Зная target (CRC32(Д-1)) и состояние
  после Д-2, можно вычислить 4 байта паддинга аналитически — без перебора.
"""

import sys
import zlib
from struct import pack


class CRCForger:
    def __init__(self):
        self.polynomial = 0xEDB88320
        self.crc32_table = [0] * 256
        self.crc32_reverse = [0] * 256
        self._build_tables()

    def _build_tables(self):
        for i in range(256):
            fwd, rev = i, i << 24
            for _ in range(8):
                # прямая таблица
                if (fwd & 1) == 1:
                    fwd = (fwd >> 1) ^ self.polynomial
                else:
                    fwd >>= 1
                self.crc32_table[i] = fwd & 0xFFFFFFFF

                # обратная таблица
                if rev & 0x80000000 == 0x80000000:
                    rev = ((rev ^ self.polynomial) << 1) | 1
                else:
                    rev <<= 1
                rev &= 0xFFFFFFFF
                self.crc32_reverse[i] = rev

    def crc32(self, s: bytes) -> int:
        """CRC32 (совместим с zlib.crc32)."""
        checksum = 0xFFFFFFFF
        for element in s:
            index = (checksum ^ element) & 0xFF
            checksum = (checksum >> 8) ^ self.crc32_table[index]
        return checksum ^ 0xFFFFFFFF

    def forge_append(self, data: bytes, target: int) -> bytes:
        """
        Возвращает 4 байта pad, такие что CRC32(data + pad) == target.
        Вставка в конец.
        """
        # A = внутреннее состояние после data
        A = 0xFFFFFFFF
        for b in data:
            A = (A >> 8) ^ self.crc32_table[(A ^ b) & 0xFF]

        # откатываем target через 4 байта A
        state = target ^ 0xFFFFFFFF
        for b in pack('<L', A)[::-1]:
            state = ((state << 8) & 0xFFFFFFFF) ^ self.crc32_reverse[state >> 24] ^ b

        return pack('<L', state)


# echo "The original document" > D1.txt
# python3 main.py gen-keys
# python3 main.py sign-crc32 -i D1.txt -o D1.sig --priv rsa_private.pem
# echo "The modified document" > D2.txt
# python3 forge_crc32.py D1.txt D2.txt D1.sig D3.txt
# python3 main.py verify-crc32 -i D3.txt -s D1.sig

def main():
    if len(sys.argv) != 5:
        print("Использование: python3 forge_crc32.py <d1> <d2> <sig> <d3>")
        print("d1  — исходный документ (Д-1)")
        print("d2  — изменённый документ (Д-2)")
        print("sig — файл подписи ЭП-1 (не используется)")
        print("d3  — выходной документ (Д-3)")
        return

    d1_path, d2_path, sig_path, d3_path = sys.argv[1:5]

    with open(d1_path, 'rb') as f:
        d1 = f.read()
    with open(d2_path, 'rb') as f:
        d2 = f.read()

    target = zlib.crc32(d1) & 0xFFFFFFFF
    current = zlib.crc32(d2) & 0xFFFFFFFF

    print(f"Д-1: {d1_path}")
    print(f"  размер: {len(d1)} байт, CRC32 = {target:08x}")
    print(f"Д-2: {d2_path}")
    print(f"  размер: {len(d2)} байт, CRC32 = {current:08x}")
    print(f"Целевой CRC32: {target:08x}")
    print()

    forger = CRCForger()
    pad = forger.forge_append(d2, target)

    d3 = d2 + pad
    print(f"Найдено дополнение: {pad.hex()}")

    with open(d3_path, 'wb') as f:
        f.write(d3)

    # Проверка
    result = zlib.crc32(d3) & 0xFFFFFFFF
    print(f"CRC32(Д-3) = {result:08x}")
    print(f"Совпадает:  {result == target}")
    print(f"Д-3: {d3_path}")


if __name__ == "__main__":
    main()
