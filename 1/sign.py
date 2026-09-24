"""
Электронная подпись RSA-SHA256 и её проверка.
Формат файла подписи - ASN.1 (раздел 4 Приложения А).

Схема:
    Подпись:  s = SHA256(m)^d mod n
    Проверка: t = s^e mod n, сравнение h % n == t % n
"""

from pyasn1.type import univ, char
from pyasn1.codec.der import encoder, decoder
from Crypto.Hash import SHA256
from Crypto.Util.number import bytes_to_long

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
    """
    Формирует электронную подпись файла (RSA-SHA256)
    и сохраняет её в ASN.1-файл подписи.

    Параметры:
      input_file     - подписываемый файл (произвольный формат)
      sign_file_out  - выходной файл подписи
      rsa_n, rsa_d   - закрытый ключ RSA
      rsa_e          - открытая экспонента (для записи в файл подписи)
      key_alias      - псевдоним ключа

    Формат файла подписи (Приложение А, раздел 4):
      SignHeader {
          keys SET OF SignRSAKeyInfo {
              algorithm   OCTET STRING  -- 0x0040 (RSA-SHA256)
              keyAlias    UTF8String
              publicKey   { modulus, publicExponent }
              parameters  SEQUENCE {}
              signature   { s }
          }
          fileInfo SEQUENCE {}
      }
    """
    print(f"[Подпись] {input_file} -> {sign_file_out}")

    # Читаем файл
    with open(input_file, 'rb') as f:
        file_data = f.read()
    print(f"Размер файла: {len(file_data)} байт")

    # SHA-256
    h = SHA256.new(file_data).digest()
    print(f"SHA-256: {h.hex()}")

    # Подпись: s = h^d mod n
    h_int = bytes_to_long(h)
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
    header['fileInfo'] = univ.Sequence() # пустая SEQUENCE (30 00)

    der = encoder.encode(header)
    print(f"ASN.1 файл подписи: {len(der)} байт")
    print(f"Начало: {der[:20].hex()}...")

    # Запись
    with open(sign_file_out, 'wb') as f:
        f.write(der)

    print(f"Файл подписи: {sign_file_out}")


# Проверка


def verify_sign(input_file: str,
                sign_file_in: str) -> bool:
    """
    Проверяет электронную подпись файла по модулю n.

    Параметры:
      input_file    - проверяемый файл
      sign_file_in  - файл подписи

    Возвращает True, если подпись верна, иначе False.
    """
    print(f"[Проверка подписи] {input_file} по {sign_file_in}")

    # Читаем файл подписи
    with open(sign_file_in, 'rb') as f:
        sign_data = f.read()
    print(f"Размер файла подписи: {len(sign_data)} байт")

    # Разбираем ASN.1
    header, _ = decoder.decode(sign_data, asn1Spec=SignHeader())

    key_set = header['keys']
    if len(key_set) == 0:
        raise ValueError("В файле подписи нет ключей")
    key_info = key_set.getComponentByPosition(0)

    # Достаём открытый ключ и подпись
    pub_key = key_info['publicKey']
    n_key = int(pub_key['modulus'])
    e_key = int(pub_key['publicExponent'])
    print(f"Открытый ключ: n={n_key.bit_length()} бит, e={e_key}")

    s = int(key_info['signature']['signature'])
    print(f"Подпись s: {s.bit_length()} бит")

    alias = str(key_info['keyAlias'])
    print(f"Псевдоним: {alias!r}")

    alg = bytes(key_info['algorithm'])
    print(f"ID алгоритма: {alg.hex()}")

    # t = s^e mod n
    t = pow(s, e_key, n_key)

    # Считаем SHA-256 проверяемого файла
    with open(input_file, 'rb') as f:
        file_data = f.read()
    h = SHA256.new(file_data).digest()
    h_int = bytes_to_long(h)
    print(f"SHA-256 файла: {h.hex()}")

    # Сравнение по модулю n
    if h_int % n_key == t % n_key:
        print("Подпись ВЕРНА")
        return True
    else:
        print("Подпись НЕВЕРНА")
        return False


def test():
    import os
    from Crypto.PublicKey import RSA

    try:
        print("Генерация RSA-2048...")
        key = RSA.generate(2048)
        n, e, d = key.n, key.e, key.d
        print(f"  n: {n.bit_length()} бит, e: {e}")

        # Готовим файл
        with open('signed.txt', 'wb') as f:
            f.write("Файл для подписи RSA-SHA256.".encode('utf-8'))
        print(f"Файл для подписи: signed.txt")

        # Подписываем
        sign_file('signed.txt', 'signed.sig', n, d, e, key_alias='testSign')

        # Проверяем правильный файл
        ok1 = verify_sign('signed.txt', 'signed.sig')
        print(f"Результат: {ok1}")
        assert ok1, "Подпись должна быть верной"

        # Ломаем файл и проверяем снова
        with open('signed.txt', 'ab') as f:
            f.write(b'!!!')

        print("Файл изменён (дописано '!!!').")
        ok2 = verify_sign('signed.txt', 'signed.sig')
        print(f"Результат на изменённом файле: {ok2}")
        assert not ok2, "Подпись должна быть неверной"

        print("Все проверки пройдены.")

    finally:
        for fname in ['signed.txt', 'signed.sig']:
            if os.path.exists(fname):
                os.remove(fname)
                print(f"Удалён: {fname}")


if __name__ == '__main__':
    test()
