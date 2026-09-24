from pyasn1.type import univ, namedtype, char


class RSAPublicKey(univ.Sequence):
    """
    Открытый ключ RSA:
      SEQUENCE {
        modulus INTEGER,
        publicExponent INTEGER
      }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('modulus', univ.Integer()),
        namedtype.NamedType('publicExponent', univ.Integer()),
    )


# Файл шифрования


class RSACiphertext(univ.Sequence):
    """
    Шифртекст симметричного ключа:
      SEQUENCE {
        ciphertext INTEGER
      }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('ciphertext', univ.Integer()),
    )


class RSAKeyInfo(univ.Sequence):
    """
    Одна последовательность ключа:
      SEQUENCE {
        algorithm   OCTET STRING   -- ID алгоритма шифрования ключа (RSA = 0x0001)
        keyAlias    UTF8String     -- псевдоним ключа
        publicKey   RSAPublicKey   -- открытый ключ RSA
        parameters  SEQUENCE {}    -- параметры криптосистемы. Для RSA пусто
        ciphertext  RSACiphertext  -- шифртекст симметричного ключа
      }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', univ.OctetString()),
        namedtype.NamedType('keyAlias', char.UTF8String()),
        namedtype.NamedType('publicKey', RSAPublicKey()),
        namedtype.NamedType('parameters', univ.Sequence()),
        namedtype.NamedType('ciphertext', RSACiphertext()),
    )


class KeySet(univ.SetOf):
    """
    Множество ключей:
      SET OF RSAKeyInfo
    """
    componentType = RSAKeyInfo()


class FileInfo(univ.Sequence):
    """
    Данные о файле:
      SEQUENCE {
        algorithm   OCTET STRING   -- ID симметричного алгоритма (AES256-CBC = 0x1082)
        fileLength  INTEGER        -- длина файла
      }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', univ.OctetString()),
        namedtype.NamedType('fileLength', univ.Integer()),
    )


class EncryptedFileHeader(univ.Sequence):
    """
    Заголовок зашифрованного файла:
      SEQUENCE {
        keys      SET OF RSAKeyInfo
        fileInfo  FileInfo
      }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('keys', KeySet()),
        namedtype.NamedType('fileInfo', FileInfo()),
    )


# Файл подписи


class SignRSASignature(univ.Sequence):
    """
    Подпись
      SEQUENCE {
        signature INTEGER  -- число s, т.е. подпись
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('signature', univ.Integer()),
    )


class SignRSAKeyInfo(univ.Sequence):
    """
    Одна последовательность подписи:
      SEQUENCE {
          algorithm   OCTET STRING      -- ID алгоритма подписи (SHA256 = 0x0040)
          keyAlias    UTF8String        -- псевдоним ключа
          publicKey   RSAPublicKey      -- открытый ключ RSA
          parameters  SEQUENCE {}       -- параметры криптосистемы. Для RSA пусто
          signature   SignRSASignature  -- подпись
      }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', univ.OctetString()),
        namedtype.NamedType('keyAlias', char.UTF8String()),
        namedtype.NamedType('publicKey', RSAPublicKey()),
        namedtype.NamedType('parameters', univ.Sequence()),
        namedtype.NamedType('signature', SignRSASignature()),
    )


class SignKeySet(univ.SetOf):
    """
    Множество подписей:
      SET OF SignRSAKeyInfo
    """
    componentType = SignRSAKeyInfo()


class SignHeader(univ.Sequence):
    """
    Заголовок файла подписи:
      SEQUENCE {
          keys      SET OF SignRSAKeyInfo
          fileInfo  SEQUENCE {}            -- дополнительных данных нет
      }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('keys', SignKeySet()),
        namedtype.NamedType('fileInfo', univ.Sequence()),
    )


# Константы


ALG_RSA         = b'\x00\x01'  # RSA
ALG_SHA256      = b'\x00\x40'  # SHA256
ALG_AES256_CBC  = b'\x10\x82'  # AES256-CBC
