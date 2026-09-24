"""
Электронная подпись RSA-CRC32 и её проверка.
Формат файла подписи - ASN.1 (раздел 4 Приложения А).

Схема:
    Подпись:  s = CRC32(m)^d mod n
    Проверка: t = s^e mod n, сравнение h % n == t % n
"""

import zlib

from pyasn1.type import univ, char
from pyasn1.codec.der import encoder, decoder

from asn1_types import (
    RSAPublicKey, SignRSASignature, SignRSAKeyInfo, SignKeySet, SignHeader,
    ALG_SHA256,
)


# Подпись


def sign_file(input_file: str,
              sign_file_out: str,
              rsa_n: int,
              rsa_d: int,
              rsa_e: int,
              key_alias: str = 'testSign') -> None:
    """Формирует электронную подпись файла (RSA-CRC32)."""
    print(f"[Подпись] {input_file} -> {sign_file_out}")

    # Читаем файл
    with open(input_file, 'rb') as f:
        file_data = f.read()
    print(f"Размер файла: {len(file_data)} байт")

    # CRC32
    h_int = zlib.crc32(file_data)
    print(f"CRC32: {h_int:08x}")

    # Подпись: s = h^d mod n
    s = pow(h_int, rsa_d, rsa_n)
    print(f"Подпись s: {s.bit_length()} бит")

    # Сборка ASN.1
    pub_key = RSAPublicKey()
    pub_key['modulus'] = univ.Integer(rsa_n)
    pub_key['publicExponent'] = univ.Integer(rsa_e)

    sig = SignRSASignature()
    sig['signature'] = univ.Integer(s)

    key_info = SignRSAKeyInfo()
    key_info['algorithm'] = univ.OctetString(ALG_SHA256)
    key_info['keyAlias'] = char.UTF8String(key_alias or '')
    key_info['publicKey'] = pub_key
    key_info['parameters'] = univ.Sequence()
    key_info['signature'] = sig

    key_set = SignKeySet()
    key_set.setComponentByPosition(0, key_info)

    header = SignHeader()
    header['keys'] = key_set
    header['fileInfo'] = univ.Sequence()

    der = encoder.encode(header)
    print(f"ASN.1 файл подписи: {len(der)} байт")

    with open(sign_file_out, 'wb') as f:
        f.write(der)

    print(f"Файл подписи: {sign_file_out}")


# Проверка


def verify_sign(input_file: str,
                sign_file_in: str) -> bool:
    """Проверяет электронную подпись файла по модулю n."""
    print(f"[Проверка подписи] {input_file} по {sign_file_in}")

    with open(sign_file_in, 'rb') as f:
        sign_data = f.read()

    header, _ = decoder.decode(sign_data, asn1Spec=SignHeader())

    key_set = header['keys']
    if len(key_set) == 0:
        raise ValueError("В файле подписи нет ключей")
    key_info = key_set.getComponentByPosition(0)

    pub_key = key_info['publicKey']
    n_key = int(pub_key['modulus'])
    e_key = int(pub_key['publicExponent'])

    s = int(key_info['signature']['signature'])

    t = pow(s, e_key, n_key)

    # Считаем CRC32 проверяемого файла
    with open(input_file, 'rb') as f:
        file_data = f.read()
    h_int = zlib.crc32(file_data)
    print(f"CRC32 файла: {h_int:08x}")

    if h_int % n_key == t % n_key:
        print("Подпись ВЕРНА")
        return True
    else:
        print("Подпись НЕВЕРНА")
        return False


# Тест


def test():
    import os
    from Crypto.PublicKey import RSA

    try:
        print("Генерация RSA-2048...")
        key = RSA.generate(2048)
        n, e, d = key.n, key.e, key.d

        with open('signed.txt', 'wb') as f:
            f.write("Файл для подписи RSA-CRC32.".encode('utf-8'))

        sign_file('signed.txt', 'signed.sig', n, d, e)

        ok1 = verify_sign('signed.txt', 'signed.sig')
        assert ok1, "Подпись должна быть верной"

        # Ломаем файл
        with open('signed.txt', 'ab') as f:
            f.write(b'!!!')

        ok2 = verify_sign('signed.txt', 'signed.sig')
        assert not ok2, "Подпись должна быть неверной"

        print("Все проверки пройдены.")

    finally:
        for fname in ['signed.txt', 'signed.sig']:
            if os.path.exists(fname):
                os.remove(fname)


if __name__ == '__main__':
    test()
