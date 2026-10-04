"""
Общие функции для клиента и сервера DH:
  - mod_inv
  - send_data / recv_data (с префиксом длины)
"""

import struct
import socket


def mod_inv(a: int, m: int) -> int:
    """Обратный элемент a^(-1) mod m (расширенный Евклид)."""
    a %= m
    t, new_t = 0, 1
    r, new_r = m, a
    while new_r != 0:
        q = r // new_r
        t, new_t = new_t, t - q * new_t
        r, new_r = new_r, r - q * new_r
    if r != 1:
        raise ValueError(f"{a} не обратим по модулю {m}")
    if t < 0:
        t += m
    return t


def send_data(sock: socket.socket, data: bytes) -> None:
    """
    Отправляет data с префиксом длины (4 байта, big-endian).
    """
    length = struct.pack('>I', len(data))
    sock.sendall(length)
    sock.sendall(data)


def recv_exact(sock: socket.socket, n: int) -> bytes | None:
    """Принимает ровно n байт."""
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)


def recv_data(sock: socket.socket) -> bytes | None:
    """
    Принимает сообщение: 4 байта длины + данные.
    """
    raw_len = recv_exact(sock, 4)
    if not raw_len:
        return None
    msg_len = struct.unpack('>I', raw_len)[0]
    return recv_exact(sock, msg_len)
