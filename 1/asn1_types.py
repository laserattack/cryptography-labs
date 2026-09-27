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

# 0:d=0  hl=4 l= 564 cons: SEQUENCE                   ← заголовок целиком
# 4:d=1  hl=4 l= 550 cons:  SET                       ← keys (SET OF)
# 8:d=2  hl=4 l= 546 cons:   SEQUENCE                 ← RSAKeyInfo
# 12:d=3 hl=2 l=   2 prim:    OCTET STRING :00 01     ← algorithm = RSA
# 16:d=3 hl=2 l=   4 prim:    UTF8STRING :test        ← keyAlias
# 22:d=3 hl=4 l= 266 cons:    SEQUENCE                ← publicKey
# 26:d=4 hl=4 l= 257 prim:     INTEGER  :B26E4A...    ← modulus (n)
# 287:d=4 hl=2 l=   3 prim:    INTEGER  :010001       ← publicExponent = 65537
# 292:d=3 hl=2 l=   0 cons:   SEQUENCE                ← parameters (пусто)
# 294:d=3 hl=4 l= 260 cons:   SEQUENCE                ← ciphertext
# 298:d=4 hl=4 l= 256 prim:    INTEGER :2ED1C7...     ← c = k^e mod n
# 558:d=1 hl=2 l=   8 cons: SEQUENCE                  ← fileInfo
# 560:d=2 hl=2 l=   2 prim:  OCTET STRING :10 82      ← algorithm = AES-256-CBC
# 564:d=2 hl=2 l=   2 prim:  INTEGER :027D            ← fileLength = 637


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

# 0:d=0   SEQUENCE                    ← заголовок (SignHeader)
# 4:d=1    SET                        ← keys (SET OF SignRSAKeyInfo)
# 8:d=2     SEQUENCE                  ← SignRSAKeyInfo
# 12:d=3     OCTET STRING :00 40      ← algorithm = RSA-SHA256
# 16:d=3     UTF8STRING :testSign     ← keyAlias
# 22:d=3     SEQUENCE                 ← publicKey
# 26:d=4      INTEGER :B26E4A...      ← modulus (n)
# 287:d=4     INTEGER :010001         ← publicExponent = 65537
# 292:d=3    SEQUENCE                 ← parameters (пусто)
# 294:d=3    SEQUENCE                 ← signature
# 298:d=4     INTEGER :...            ← s = h^d mod n
# 558:d=1  SEQUENCE                   ← fileInfo (пусто)


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
