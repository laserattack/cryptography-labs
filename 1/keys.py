"""
Генерация и загрузка ключей:
  - RSA (2048 бит по умолчанию) -> PEM-файлы
  - AES-256 (32 байта)          -> бинарный файл

Используется в main.py для режимов:
  - генерация ключей
  - шифрование/расшифрование
  - подпись/проверка
"""

import os
from Crypto.PublicKey import RSA


#  Генерация


def generate_keys(bits: int = 2048,
                  private_pem: str = 'rsa_private.pem',
                  public_pem: str = 'rsa_public.pem',
                  aes_key_file: str = 'aes_key.bin') -> None:
    """
    Генерирует пару ключей RSA и случайный ключ AES-256,
    сохраняет их в файлы.

    Параметры:
      bits          - размер ключа RSA (бит), по умолчанию 2048
      private_pem   - файл для закрытого ключа RSA (PEM)
      public_pem    - файл для открытого ключа RSA (PEM)
      aes_key_file  - файл для ключа AES-256 (32 байта)
    """
    print(f"[Генерация ключей] RSA-{bits}")

    # RSA
    key = RSA.generate(bits)

    with open(private_pem, 'wb') as f:
        f.write(key.export_key('PEM'))
    print(f"Закрытый RSA: {private_pem}")

    with open(public_pem, 'wb') as f:
        f.write(key.publickey().export_key('PEM'))
    print(f"Открытый RSA: {public_pem}")

    # AES-256 (32 байта)
    aes_key = os.urandom(32)
    with open(aes_key_file, 'wb') as f:
        f.write(aes_key)
    print(f"AES-256: {aes_key_file}")
    print(f"Ключ: {aes_key.hex()}")

    phi = (key.p - 1) * (key.q - 1)

    print(f"n: {key.n.bit_length()} бит")
    print(f"e: {key.e}")
    print(f"p: {key.p}")
    print(f"q: {key.q}")
    print(f"phi: {phi}")


#  Загрузка


def load_public_key(pem_file: str) -> tuple[int, int]:
    """
    Загружает открытый ключ RSA из PEM-файла.
    Возвращает (n, e).
    """
    with open(pem_file, 'rb') as f:
        key = RSA.import_key(f.read())
    return key.n, key.e


def load_private_key(pem_file: str) -> tuple[int, int, int]:
    """
    Загружает закрытый ключ RSA из PEM-файла.
    Возвращает (n, d, e).
    """
    with open(pem_file, 'rb') as f:
        key = RSA.import_key(f.read())
    return key.n, key.d, key.e


def load_aes_key(key_file: str | None) -> bytes | None:
    """
    Загружает AES-ключ из файла.
    Возвращает 32 байта или None, если файл не указан/некорректен.
    """
    if not key_file:
        return None
    with open(key_file, 'rb') as f:
        key = f.read()
    if len(key) != 32:
        print(f"AES-ключ {len(key)} байт, ожидалось 32. "
              f"Будет сгенерирован случайный.")
        return None
    return key


#  Тест


def test():
    import os

    created = []

    try:
        print("Генерация ключей...")
        generate_keys(2048, 'rsa_priv.pem', 'rsa_pub.pem', 'aes.bin')
        created += ['rsa_priv.pem', 'rsa_pub.pem', 'aes.bin']

        print("Загрузка открытого ключа...")
        n1, e1 = load_public_key('rsa_pub.pem')
        print(f"n: {n1.bit_length()} бит, e: {e1}")

        print("Загрузка закрытого ключа...")
        n2, d2, e2 = load_private_key('rsa_priv.pem')
        print(f"n: {n2.bit_length()} бит, d: {d2.bit_length()} бит, e: {e2}")

        print("Загрузка AES-ключа...")
        k = load_aes_key('aes.bin')
        print(f"AES: {k.hex()}")

        # Проверки
        assert n1 == n2, "n должен совпадать"
        assert e1 == e2, "e должен совпадать"
        assert k is not None and len(k) == 32, "AES-ключ должен быть 32 байта"
        assert d2.bit_length() > 1000, "d должен быть большим числом"

        print("Все проверки пройдены.")

    finally:
        for fname in created:
            if os.path.exists(fname):
                os.remove(fname)
                print(f"Удалён: {fname}")


if __name__ == '__main__':
    test()
