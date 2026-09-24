"""
Криптографические операции: шифрование и расшифрование файла
по схеме RSA + AES-256-CBC с ASN.1-заголовком.

Формат зашифрованного файла:
    [ASN.1 header] [IV 16 байт] [AES-256-CBC ciphertext]

Схема:
    1. Генерируется (или берётся) 32-байтовый ключ AES-256.
    2. Ключ AES шифруется открытым ключом RSA: c = k^e mod n.
    3. Сообщение шифруется AES-256-CBC со случайным IV.
"""

from pyasn1.type import univ, char
from pyasn1.codec.der import encoder, decoder
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Util.number import bytes_to_long, long_to_bytes

from asn1_types import (
    RSAPublicKey, RSACiphertext, RSAKeyInfo, KeySet, FileInfo,
    EncryptedFileHeader,
    ALG_RSA, ALG_AES256_CBC,
)


# Шифрование


def encrypt_file(input_file: str,
                 output_file: str,
                 rsa_n: int,
                 rsa_e: int,
                 key_alias: str = 'test',
                 aes_key: bytes | None = None) -> None:
    """
    Шифрует файл по схеме RSA + AES-256-CBC.

    Параметры:
      input_file    - путь к шифруемому файлу
      output_file   - путь к зашифрованному файлу
      rsa_n, rsa_e  - открытый ключ RSA
      key_alias     - псевдоним ключа (для ASN.1, таблица А.4)
      aes_key       - 32-байтовый ключ AES; если None - генерируется случайно

    Результат (файл):
      [ASN.1 header] [IV 16 байт] [AES-256-CBC ciphertext]
    """
    print(f"[Шифрование] {input_file} -> {output_file}")

    # Ключ AES-256 (32 байта)
    if aes_key is None:
        aes_key = get_random_bytes(32)
        print(f"Сгенерирован AES-256 ключ: {aes_key.hex()}")
    if len(aes_key) != 32:
        raise ValueError(f"AES-256 требует ключ ровно 32 байта, получено {len(aes_key)}")

    # Случайный IV
    iv = get_random_bytes(16)
    print(f"IV: {iv.hex()}")

    # RSA-шифрование ключа AES: c = k^e mod n
    m = bytes_to_long(aes_key)
    c = pow(m, rsa_e, rsa_n)
    print(f"RSA: c = k^e mod n, длина c = {c.bit_length()} бит")

    # Сборка ASN.1-заголовка

    # Открытый ключ
    pub_key = RSAPublicKey()
    pub_key['modulus'] = univ.Integer(rsa_n)
    pub_key['publicExponent'] = univ.Integer(rsa_e)

    # Шифртекст ключа AES
    ct = RSACiphertext()
    ct['ciphertext'] = univ.Integer(c)

    # RSAKeyInfo
    key_info = RSAKeyInfo()
    key_info['algorithm'] = univ.OctetString(ALG_RSA)
    key_info['keyAlias'] = char.UTF8String(key_alias or '')
    key_info['publicKey'] = pub_key
    key_info['parameters'] = univ.Sequence()
    key_info['ciphertext'] = ct

    # Множество ключей
    key_set = KeySet()
    key_set.setComponentByPosition(0, key_info)

    # Читаем сообщение
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    print(f"Размер сообщения: {len(plaintext)} байт")

    # FileInfo
    file_info = FileInfo()
    file_info['algorithm'] = univ.OctetString(ALG_AES256_CBC)
    file_info['fileLength'] = univ.Integer(len(plaintext))

    # Заголовок целиком
    header = EncryptedFileHeader()
    header['keys'] = key_set
    header['fileInfo'] = file_info

    header_der = encoder.encode(header)
    print(f"ASN.1 заголовок: {len(header_der)} байт, начало: {header_der[:20].hex()}...")

    # Шифрование AES-256-CBC
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = cipher_aes.encrypt(pad(plaintext, AES.block_size))
    print(f"AES ciphertext: {len(ciphertext)} байт")

    # Запись файла: header || IV || ciphertext
    with open(output_file, 'wb') as f:
        f.write(header_der)
        f.write(iv)
        f.write(ciphertext)

    print(f"Зашифрованный файл: {output_file}")


# Расшифрование


def decrypt_file(input_file: str,
                 output_file: str,
                 rsa_n: int,
                 rsa_d: int) -> None:
    """
    Расшифровывает файл, созданный encrypt_file.

    Параметры:
      input_file    - зашифрованный файл
      output_file   - расшифрованный файл
      rsa_n, rsa_d  - закрытый ключ RSA
    """
    print(f"[Расшифрование] {input_file} -> {output_file}")

    # Читаем файл
    with open(input_file, 'rb') as f:
        data = f.read()
    print(f"Размер зашифрованного файла: {len(data)} байт")

    # Разбираем ASN.1-заголовок
    header, remaining = decoder.decode(data, asn1Spec=EncryptedFileHeader())
    print(f"Заголовок разобран, после него осталось {len(remaining)} байт")

    # Достаём множество ключей
    key_set = header['keys']
    if len(key_set) == 0:
        raise ValueError("В заголовке нет ключей")
    key_info = key_set.getComponentByPosition(0)

    alias = str(key_info['keyAlias'])
    print(f"Псевдоним ключа: {alias!r}")

    # RSA-расшифрование ключа AES: k = c^d mod n
    c = int(key_info['ciphertext']['ciphertext'])
    m = pow(c, rsa_d, rsa_n)
    aes_key = long_to_bytes(m, 32)
    if len(aes_key) != 32:
        raise ValueError("Не удалось восстановить 32-байтовый ключ AES")
    print(f"AES-256 ключ: {aes_key.hex()}")

    # IV и шифртекст
    if len(remaining) < 16:
        raise ValueError("Файл слишком короткий: нет IV")
    iv = remaining[:16]
    ciphertext = remaining[16:]
    print(f"IV: {iv.hex()}")
    print(f"AES ciphertext: {len(ciphertext)} байт")

    if len(ciphertext) == 0 or len(ciphertext) % 16 != 0:
        raise ValueError("Некорректная длина AES-шифртекста (должна быть кратна 16)")

    # AES-256-CBC
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher_aes.decrypt(ciphertext), AES.block_size)

    # Сверка длины с заголовком
    expected_len = int(header['fileInfo']['fileLength'])
    if len(plaintext) != expected_len:
        print(f"Длина {len(plaintext)} != заявленной {expected_len}")
    else:
        print(f"Длина совпадает с заявленной: {len(plaintext)} байт")

    # Запись
    with open(output_file, 'wb') as f:
        f.write(plaintext)

    print(f"Расшифрованный файл: {output_file}")


def test():
    import os
    from Crypto.PublicKey import RSA

    try:
        # RSA-2048
        print("Генерация RSA-2048...")
        key = RSA.generate(2048)
        n, e, d = key.n, key.e, key.d

        # Сообщение
        msg = "Это тестовое сообщение для RSA + AES-256-CBC + ASN.1.".encode('utf-8')
        with open('msg.txt', 'wb') as f:
            f.write(msg)
        print(f"Сообщение: {len(msg)} байт")

        # AES256-ключ (32 байта)
        aes_key = os.urandom(32)
        print(f"AES-256 ключ: {aes_key.hex()}")

        # Шифруем
        encrypt_file('msg.txt', 'msg.enc', n, e, key_alias='test', aes_key=aes_key)

        # Расшифровываем
        decrypt_file('msg.enc', 'msg.dec', n, d)

        # Сверяем
        with open('msg.txt', 'rb') as f:  orig = f.read()
        with open('msg.dec', 'rb') as f:  dec  = f.read()

        print(f"Исходное: {orig!r}")
        print(f"Расшифровано: {dec!r}")
        print(f"Совпадает: {orig == dec}")

    finally:
        for fname in ('msg.txt', 'msg.enc', 'msg.dec'):
            if os.path.exists(fname):
                os.remove(fname)
                print(f"Удалён: {fname}")


if __name__ == '__main__':
    test()
