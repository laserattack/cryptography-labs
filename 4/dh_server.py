"""
Сервер протокола Диффи-Хеллмана.

Использование:
    python3 dh_server.py [port]

Сценарий:
    1. Слушать TCP
    2. Принять подключение
    3. Получить Message1 (a^x, p, a)
    4. Секрет y, публичное B = a^y mod p
    5. Отправить Message2 (a^y)
    6. K = (a^x)^y mod p
    7. AES-ключ = K mod 2^256
    8. Получить Message3 + IV + шифртекст
    9. Расшифровать, вывести на экран
"""

import os
import socket
import sys
import threading

from Crypto.Cipher import AES
from pyasn1.type import univ, char
from pyasn1.codec.der import encoder, decoder

from dh_asn1 import (
    DHMessage2, DHKeyInfo2, DHKeySet2, DHHeader2,
    AESHeader,
    ALG_DH, KEY_ALIAS,
)
from dh_common import send_data, recv_data
from dh_params import (
    generate_secret, compute_public, compute_shared,
)


#  Разбор / сборка сообщений


def parse_message1(data: bytes) -> tuple[int, int, int]:
    """
    Разбирает первое сообщение: (p, a, a^x).
    """
    from dh_asn1 import DHHeader1
    header, _ = decoder.decode(data, asn1Spec=DHHeader1())
    key = header['keys'].getComponentByPosition(0)
    p = int(key['parameters']['prime'])
    a = int(key['parameters']['generator'])
    A = int(key['ciphertext']['value'])
    return p, a, A


def build_message2(B: int):
    """Собирает второе сообщение: a^y."""
    cipher = DHMessage2()
    cipher['value'] = univ.Integer(B)

    key = DHKeyInfo2()
    key['algorithm'] = univ.OctetString(ALG_DH)
    key['keyAlias'] = char.UTF8String(KEY_ALIAS)
    key['publicKey'] = univ.Sequence()
    key['parameters'] = univ.Sequence()
    key['ciphertext'] = cipher

    key_set = DHKeySet2()
    key_set.setComponentByPosition(0, key)

    header = DHHeader2()
    header['keys'] = key_set
    header['fileInfo'] = univ.Sequence()

    return header


def parse_message3(payload: bytes) -> tuple[int, bytes, bytes]:
    """
    Разбирает третье сообщение: (fileLength, iv, ciphertext).
    """
    header, remaining = decoder.decode(payload, asn1Spec=AESHeader())
    file_length = int(header['fileInfo']['fileLength'])

    iv = remaining[:16]
    ciphertext = remaining[16:]
    return file_length, iv, ciphertext


#  AES


def aes_decrypt(ciphertext: bytes, key: bytes, iv: bytes,
                original_length: int) -> bytes:
    """AES-256-CBC расшифровка, обрезка до original_length."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    return decrypted[:original_length]


#  Обработка клиента


def handle_client(conn: socket.socket, addr: tuple) -> None:
    """Обрабатывает одного клиента."""
    print(f"[+] Клиент подключился: {addr}")

    try:
        # 1. Message1
        print("[1] Ожидание Message1 (a^x, p, a)...")
        data = recv_data(conn)
        if data is None:
            print("Клиент закрыл соединение")
            return

        p, a, A = parse_message1(data)
        print(f"p = {hex(p)}")
        print(f"a = {hex(a)}")
        print(f"a^x = {hex(A)}")

        # 2. Секрет y
        print("[2] Генерация секрета y и вычисление a^y...")
        # q ≈ (p-1)/2 — для generate_secret нужен верхний предел
        q = (p - 1) // 2
        y = generate_secret(q)
        B = compute_public(a, y, p)
        print(f"y = {hex(y)}")
        print(f"a^y = {hex(B)}")

        # 3. Отправка Message2
        print("[3] Отправка Message2 (a^y)...")
        msg2 = build_message2(B)
        send_data(conn, encoder.encode(msg2))

        # 4. Общий секрет
        print("[4] Вычисление K = (a^x)^y mod p...")
        K = compute_shared(A, y, p)
        print(f"K = {hex(K)}")

        # 5. AES-ключ
        print("[5] Получение ключа AES: K mod 2^256...")
        aes_key_int = K % (2 ** 256)
        aes_key = aes_key_int.to_bytes(32, 'big')
        print(f"AES-ключ = {aes_key.hex()}")

        # 6. Message3
        print("[6] Ожидание Message3 (AESHeader + IV + ciphertext)...")
        payload = recv_data(conn)
        if payload is None:
            print("Клиент закрыл соединение")
            return

        file_length, iv, ciphertext = parse_message3(payload)
        print(f"fileLength = {file_length}")
        print(f"IV = {iv.hex()}")
        print(f"Шифртекст: {len(ciphertext)} байт")

        # 7. Расшифровка
        print("[7] Расшифровка AES-256-CBC...")
        message = aes_decrypt(ciphertext, aes_key, iv, file_length)

        # 8. Вывод
        print("[+] Принятое сообщение:")
        try:
            print(message.decode('utf-8'))
        except UnicodeDecodeError:
            print(f"(hex) {message.hex()}")

    except Exception as e:
        print(f"[-] Ошибка: {type(e).__name__}: {e}")
    finally:
        conn.close()
        print(f"[*] Соединение с {addr} закрыто")


#  Запуск сервера


def run_server(host: str = '0.0.0.0', port: int = 8888) -> None:
    """Запускает сервер."""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_sock.bind((host, port))
        server_sock.listen(5)
        print(f"[+] Сервер запущен на {host}:{port}")
        print("[*] Ожидание подключений...")

        while True:
            conn, addr = server_sock.accept()
            thread = threading.Thread(
                target=handle_client, args=(conn, addr), daemon=True
            )
            thread.start()

    except KeyboardInterrupt:
        print("[*] Сервер остановлен")
    finally:
        server_sock.close()


#  Точка входа


# python3 dh_server.py 8888
def main():
    port = 8888
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print(f"Некорректный порт, использую {port}")

    run_server(port=port)


if __name__ == '__main__':
    main()
