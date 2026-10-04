"""
ASN.1-структуры для протокола Диффи-Хеллмана.
"""

from pyasn1.type import univ, namedtype, char


#  Параметры группы

class DHParameters(univ.Sequence):
    """Параметры группы: p, a."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('prime', univ.Integer()),      # простое число 𝑝
        namedtype.NamedType('generator', univ.Integer()),  # образующая a
    )


#  Сообщение 1: клиент -> сервер

class DHMessage1(univ.Sequence):
    """Шифртекст: a^x."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('value', univ.Integer()),  # a^x
    )


class DHKeyInfo1(univ.Sequence):
    """Один ключ первого сообщения."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', univ.OctetString()),  # идентификатор алгоритма
        namedtype.NamedType('keyAlias', char.UTF8String()),    # имя ключа
        namedtype.NamedType('publicKey', univ.Sequence()),     # знаечение открытого ключа - не используется
        namedtype.NamedType('parameters', DHParameters()),     # параметры криптосистемы
        namedtype.NamedType('ciphertext', DHMessage1()),       # шифртекст  a^x
    )


class DHKeySet1(univ.SetOf):
    componentType = DHKeyInfo1()


class DHHeader1(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('keys', DHKeySet1()),          # мн-во ключей
        namedtype.NamedType('fileInfo', univ.Sequence()),  # не используется
    )


#  Сообщение 2: сервер -> клиент

class DHMessage2(univ.Sequence):
    """Шифртекст: a^y."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('value', univ.Integer()),  # a^y
    )


class DHKeyInfo2(univ.Sequence):
    """Один ключ второго сообщения."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', univ.OctetString()),  # идентификатор алгоритма
        namedtype.NamedType('keyAlias', char.UTF8String()),    # имя ключа
        namedtype.NamedType('publicKey', univ.Sequence()),     # знаечение открытого ключа - не используется
        namedtype.NamedType('parameters', univ.Sequence()),    # параметры криптосистемы - не используется
        namedtype.NamedType('ciphertext', DHMessage2()),       # шифртекст a^y
    )


class DHKeySet2(univ.SetOf):
    componentType = DHKeyInfo2()


class DHHeader2(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('keys', DHKeySet2()),          # мн-во ключей
        namedtype.NamedType('fileInfo', univ.Sequence()),  # не используется
    )


#  Сообщение 3: клиент-> сервер: AES-шифртекст

# Из установленного между клиентом и сервером закрытого ключа a^xy
# получается ключ AES: a^xy mod 256

# Далее клиент и сервер могут обмениваться сообщениями зашифрованными
# алгоритмом AES.

# По лабе сервер принимает, расшифровывает и выводит на экран принятое
# сообщение.

class AESFileInfo(univ.Sequence):
    """Параметры файла (как в лабе №1)."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', univ.OctetString()),  # идентификатор AEC_CBC: 10 82
        namedtype.NamedType('fileLength', univ.Integer()),     # длина сообщения
    )


class AESHeader(univ.Sequence):
    """Заголовок AES-сообщения."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('keys', univ.SetOf()),       # мн-во ключей - не используется
        namedtype.NamedType('fileInfo', AESFileInfo()),  # параметры файла (сообщения)
    )


#  Константы

ALG_DH       = b'\x00\x21' # ID протокола DH
ALG_AES_CBC  = b'\x10\x82' # ID AES-CBC
KEY_ALIAS    = 'dh'
