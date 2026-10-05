from pyasn1.type import univ, char
from pyasn1.codec.der import encoder, decoder

from gostcrypto import gosthash
import random

from ec_math import ECPoint, EC_INF, add_points, scalar_mul, mod_inv

from asn1_types import (
    PublicKey, FieldParams, CurveParams, GeneratorParams,
    SystemParams, Signature, KeyInfo, KeySet, SignatureHeader,
    ALG_GOST_SIGN,
)


# Параметры кривой (из parameters.md)
p = 57896044630612021680684936114742422271145183870487080309667128995208157569947
q = 28948022315306010840342468057371211135571302038761442251594012761075345324491
a = 1
b = 19750513962881385028059495396984460236743646692126413053976069443380491067343
xP = 43490682822985073571091311123441225129011272278165566160439297012894969619553
yP = 53273700124912449490307054424387372532482586733448415163119878489682918137700

P = ECPoint(xP, yP)


def hash_message(message: bytes) -> int:
    """
    Хеш сообщения по ГОСТ Р 34.11-2012 (Стрибог-256),
    приведённый по модулю q с заменой нуля на единицу.
    """
    h = gosthash.GOST34112012('streebog256', bytearray(message))
    digest = h.digest()

    a = int.from_bytes(digest, byteorder='big')
    e = a % q

    if e == 0:
        e = 1

    return e


def generate_keypair():
    """
    Генерация ключевой пары по ГОСТ Р 34.10-2018.
    """
    d = random.randint(1, q - 1)
    Q = scalar_mul(d, P, a, p)
    return d, Q


def sign(message: bytes, d: int) -> tuple[int, int]:
    """
    Формирование подписи по ГОСТ Р 34.10-2018.
    """
    e = hash_message(message)  # Хэш приведённый по модулю q с заменой нуля на единицу

    while True:
        k = random.randint(1, q - 1) # Вырабатывает случайный показатель 𝑘
        C = scalar_mul(k, P, a, p)   # Вычисляет точку 𝐶 ← 𝑘𝑃
        r = C.x % q                  # 𝑟 ≡ С.x (𝑚𝑜𝑑 𝑞)
        if r == 0:
            continue

        s = (r * d + k * e) % q      # 𝑠 ← (𝑟𝑑 + 𝑘𝑒)
        if s == 0:
            continue

        return r, s


def verify(message: bytes, r: int, s: int, Q: ECPoint) -> bool:
    """
    Проверка подписи по ГОСТ Р 34.10-2018.
    """
    if not (0 < r < q and 0 < s < q):
        return False

    e = hash_message(message)  # Хэш приведённый по модулю q с заменой нуля на единицу
    v = mod_inv(e, q)          # Обратное e по модулю q
    z1 = (s * v) % q           # 𝑧1 ≡ 𝑠𝑣(𝑚𝑜𝑑 𝑞)
    z2 = (-r * v) % q          # 𝑧2 ≡ −𝑟𝑣(𝑚𝑜𝑑 𝑞)

    # 𝐶 = 𝑧1𝑃 + 𝑧2𝑄
    C = add_points(
        scalar_mul(z1, P, a, p),
        scalar_mul(z2, Q, a, p),
        a, p
    )

    if C.is_infinity:
        return False

    # 𝑅 ≡ C.x (𝑚𝑜𝑑 𝑞)
    R = C.x % q

    return R == r


# коровые ф-ии закончились, далее работа с файлами, asn1 и пр


KEY_ALIAS = 'gostSignKey'


def sign_file(input_file: str, output_file: str, d: int, Q: ECPoint,
              alias: str = KEY_ALIAS) -> None:
    """
    Формирует подпись файла и сохраняет ASN.1-файл подписи.

    Параметры:
      input_file  — файл для подписи
      output_file — файл подписи (.sig)
      d           — закрытый ключ
      Q           — открытый ключ
      alias       — псевдоним ключа
    """
    # 1. Читаем файл
    with open(input_file, 'rb') as f:
        data = f.read()

    # 2. Подпись
    r, s = sign(data, d)

    # 3. ASN.1: открытый ключ
    pub_key = PublicKey()
    pub_key['x'] = univ.Integer(Q.x)
    pub_key['y'] = univ.Integer(Q.y)

    # 4. ASN.1: параметры поля
    field_params = FieldParams()
    field_params['prime'] = univ.Integer(p)

    # 5. ASN.1: параметры кривой
    curve_params = CurveParams()
    curve_params['a'] = univ.Integer(a)
    curve_params['b'] = univ.Integer(b)

    # 6. ASN.1: образующая точка
    generator_params = GeneratorParams()
    generator_params['x'] = univ.Integer(xP)
    generator_params['y'] = univ.Integer(yP)

    # 7. ASN.1: параметры криптосистемы
    system_params = SystemParams()
    system_params['field'] = field_params
    system_params['curve'] = curve_params
    system_params['generator'] = generator_params
    system_params['order'] = univ.Integer(q)

    # 8. ASN.1: подпись
    signature = Signature()
    signature['r'] = univ.Integer(r)
    signature['s'] = univ.Integer(s)

    # 9. ASN.1: один ключ
    key_info = KeyInfo()
    key_info['algorithm'] = univ.OctetString(ALG_GOST_SIGN)
    key_info['keyAlias'] = char.UTF8String(alias)
    key_info['publicKey'] = pub_key
    key_info['parameters'] = system_params
    key_info['signature'] = signature

    # 10. ASN.1: множество ключей
    key_set = KeySet()
    key_set.setComponentByPosition(0, key_info)

    # 11. ASN.1: заголовок
    header = SignatureHeader()
    header['keys'] = key_set
    header['fileInfo'] = univ.Sequence()

    # 12. Кодируем и записываем
    der = encoder.encode(header)

    with open(output_file, 'wb') as f:
        f.write(der)

    print(f"Подпись сохранена: {output_file}")
    print(f"Размер: {len(der)} байт")
    print(f"r = {r}")
    print(f"s = {s}")


def verify_file(sig_filename: str, data_filename: str) -> bool:
    """
    Проверяет подпись из ASN.1-файла.

    Параметры:
      sig_filename  — файл подписи (.sig)
      data_filename — файл данных

    Возвращает:
      True, если подпись верна
    """
    with open(sig_filename, 'rb') as f:
        sig_data = f.read()

    header, _ = decoder.decode(sig_data, asn1Spec=SignatureHeader())

    key_info = header['keys'].getComponentByPosition(0)

    xQ = int(key_info['publicKey']['x'])
    yQ = int(key_info['publicKey']['y'])
    Q = ECPoint(xQ, yQ)

    r = int(key_info['signature']['r'])
    s = int(key_info['signature']['s'])

    with open(data_filename, 'rb') as f:
        data = f.read()

    return verify(data, r, s, Q)


if __name__ == '__main__':
    import os

    # 1. Ключи
    d, Q = generate_keypair()
    print(f"d = {d}")
    print(f"Q = {Q}")

    # 2. Файл
    with open('test.txt', 'wb') as f:
        f.write(b"Test message for GOST signature")

    # 3. Подпись
    sign_file('test.txt', 'test.sig', d, Q)

    # 4. Проверка правильного файла
    assert verify_file('test.sig', 'test.txt') is True

    # 5. Изменённый файл
    with open('test.txt', 'ab') as f:
        f.write(b"!!!")
    assert verify_file('test.sig', 'test.txt') is False

    # 6. Уборка
    os.remove('test.txt')
    os.remove('test.sig')

    print("успех")
