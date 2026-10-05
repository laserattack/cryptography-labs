"""
Клиент протокола Диффи-Хеллмана.

Использование:
    python3 dh_client.py <config.json> <file>

Сценарий:
    1. Чтение файла
    2. Генерация p, a
    3. Секрет x, публичное A = a^x mod p
    4. TCP-подключение к серверу
    5. Отправка Message1 (a^x, p, a)
    6. Получение Message2 (a^y)
    7. K = (a^y)^x mod p
    8. AES-ключ = K mod 2^256
    9. AES-CBC шифрование файла (паддинг 0x03)
    10. Отправка Message3 (AES-заголовок) + AES-шифртекст
"""

import json
import os
import socket
import sys

from Crypto.Cipher import AES
from pyasn1.type import univ, char
from pyasn1.codec.der import encoder, decoder

from dh_asn1 import (
    DHParameters, DHMessage1, DHKeyInfo1, DHKeySet1, DHHeader1,
    DHMessage2, DHKeyInfo2, DHKeySet2, DHHeader2,
    AESFileInfo, AESHeader,
    ALG_DH, ALG_AES_CBC, KEY_ALIAS,
)
from dh_common import send_data, recv_data
from dh_params import (
    generate_safe_prime, generate_generator, generate_secret,
    compute_public, compute_shared,
)


#  Конфиг


def load_config(path: str) -> dict:
    """Загружает конфиг клиента."""
    with open(path, 'r', encoding='utf-8') as f:
        config = json.load(f)

    required = ['server_host', 'server_port', 'connection_timeout']
    for field in required:
        if field not in config:
            raise ValueError(f"В конфиге нет поля '{field}'")

    return config


#  AES


def aes_encrypt(data: bytes, key: bytes) -> tuple[bytes, bytes]:
    """
    AES-256-CBC с паддингом 0x03.

    Возвращает (iv, ciphertext).
    """
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # паддинг 0x03 до кратности 16
    pad_len = (16 - len(data) % 16) % 16
    if pad_len > 0:
        data += bytes([0x03] * pad_len)

    ciphertext = cipher.encrypt(data)
    return iv, ciphertext


#  Сборка сообщений


def build_message1(p: int, a: int, A: int):
    """Собирает первое сообщение: a^x, p, a."""
    # параметры
    params = DHParameters()
    params['prime'] = univ.Integer(p)
    params['generator'] = univ.Integer(a)

    # шифртекст
    cipher = DHMessage1()
    cipher['value'] = univ.Integer(A)

    # ключ
    key = DHKeyInfo1()
    key['algorithm'] = univ.OctetString(ALG_DH)
    key['keyAlias'] = char.UTF8String(KEY_ALIAS)
    key['publicKey'] = univ.Sequence()
    key['parameters'] = params
    key['ciphertext'] = cipher

    key_set = DHKeySet1()
    key_set.setComponentByPosition(0, key)

    header = DHHeader1()
    header['keys'] = key_set
    header['fileInfo'] = univ.Sequence()

    return header


def parse_message2(data: bytes) -> int:
    """Разбирает второе сообщение: a^y."""
    header, _ = decoder.decode(data, asn1Spec=DHHeader2())
    key = header['keys'].getComponentByPosition(0)
    cipher = key['ciphertext']
    return int(cipher['value'])


def build_message3(file_length: int):
    """Собирает заголовок третьего сообщения (для AES)."""
    file_info = AESFileInfo()
    file_info['algorithm'] = univ.OctetString(ALG_AES_CBC)
    file_info['fileLength'] = univ.Integer(file_length)

    header = AESHeader()
    header['keys'] = univ.SetOf()
    header['fileInfo'] = file_info

    return header


#  Основной сценарий


def run_client(filename: str, config: dict) -> bool:
    """Основной сценарий клиента."""
    # 1. Чтение файла
    if not os.path.exists(filename):
        print(f"Файл '{filename}' не найден")
        return False

    with open(filename, 'rb') as f:
        file_data = f.read()
    original_length = len(file_data)
    print(f"Файл '{filename}' загружен, размер: {original_length} байт")

    # 2. Генерация параметров
    print("[1] Генерация параметров группы...")
    p, q = generate_safe_prime(512)
    a = generate_generator(p, q)
    print(f"p = {hex(p)}")
    print(f"a = {hex(a)}")

    # 3. Секрет и публичное значение
    print("[2] Генерация секрета x и вычисление a^x...")
    x = generate_secret(q)
    A = compute_public(a, x, p)
    print(f"x = {hex(x)}")
    print(f"a^x = {hex(A)}")

    # 4. Подключение
    host = config['server_host']
    port = config['server_port']
    timeout = config['connection_timeout']

    print(f"[3] Подключение к {host}:{port}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((host, port))
        print("Подключение установлено")

        # 5. Отправка Message1
        print("[4] Отправка Message1 (a^x, p, a)...")
        msg1 = build_message1(p, a, A)
        msg1_der = encoder.encode(msg1)
        with open('msg1.asn1', 'wb') as f:
            f.write(msg1_der)
        print(f"Message1 сохранён: msg1.asn1 ({len(msg1_der)} байт)")
        send_data(sock, msg1_der)

        # 6. Получение Message2
        print("[5] Ожидание Message2 (a^y)...")
        data = recv_data(sock)
        if data is None:
            print("Ошибка: сервер закрыл соединение")
            return False

        # сохранить в файл
        with open('msg2.asn1', 'wb') as f:
            f.write(data)
        print(f"Message2 сохранён: msg2.asn1 ({len(data)} байт)")

        B = parse_message2(data)
        print(f"a^y = {hex(B)}")

        # 7. Общий секрет
        print("[6] Вычисление K = (a^y)^x mod p...")
        K = compute_shared(B, x, p)
        print(f"K = {hex(K)}")

        # 8. AES-ключ
        print("[7] Получение ключа AES: K mod 2^256...")
        aes_key_int = K % (2 ** 256)
        aes_key = aes_key_int.to_bytes(32, 'big')
        print(f"AES-ключ = {aes_key.hex()}")

        # 9. Шифрование
        print("[8] Шифрование файла (AES-256-CBC)...")
        iv, ciphertext = aes_encrypt(file_data, aes_key)
        print(f"IV = {iv.hex()}")
        print(f"Шифртекст: {len(ciphertext)} байт")

        # 10. Отправка Message3 + IV + шифртекст
        print("[9] Отправка Message3 + IV + шифртекст...")
        msg3 = build_message3(original_length)
        header_der = encoder.encode(msg3)

        # сохранить ASN.1-заголовок в файл
        with open('msg3.asn1', 'wb') as f:
            f.write(header_der)
        print(f"Message3 сохранён: msg3.asn1 ({len(header_der)} байт)")

        # Заголовок || IV || шифртекст
        payload = header_der + iv + ciphertext
        send_data(sock, payload)

        print("[+] Сообщение отправлено")
        return True

    except socket.timeout:
        print(f"Ошибка: таймаут подключения")
        return False
    except ConnectionRefusedError:
        print(f"Ошибка: сервер {host}:{port} недоступен")
        return False
    except Exception as e:
        print(f"Ошибка: {type(e).__name__}: {e}")
        return False
    finally:
        sock.close()
        print("Соединение закрыто")


#  Точка входа


# сервер должен быть запущен, далее:
# echo "hello, DH!" > msg.txt
# python3 dh_client.py config.json msg.txt
def main():
    if len(sys.argv) != 3:
        print("Использование: python3 dh_client.py <config.json> <file>")
        return

    config_path = sys.argv[1]
    filename = sys.argv[2]

    try:
        config = load_config(config_path)
    except FileNotFoundError:
        print(f"Конфиг '{config_path}' не найден")
        sys.exit(1)
    except Exception as e:
        print(f"Ошибка конфига: {e}")
        sys.exit(1)

    success = run_client(filename, config)
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
