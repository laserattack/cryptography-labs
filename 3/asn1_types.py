from pyasn1.type import univ, namedtype, char


class PublicKey(univ.Sequence):
    """Открытый ключ Q = (x, y)."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('x', univ.Integer()),
        namedtype.NamedType('y', univ.Integer()),
    )


class FieldParams(univ.Sequence):
    """Параметры поля: простое p."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('prime', univ.Integer()),
    )


class CurveParams(univ.Sequence):
    """Параметры кривой: a, b."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('a', univ.Integer()),
        namedtype.NamedType('b', univ.Integer()),
    )


class GeneratorParams(univ.Sequence):
    """Образующая точка P = (x, y)."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('x', univ.Integer()),
        namedtype.NamedType('y', univ.Integer()),
    )


class SystemParams(univ.Sequence):
    """Параметры криптосистемы."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('field', FieldParams()),         # параметры поля
        namedtype.NamedType('curve', CurveParams()),         # параметры кривой
        namedtype.NamedType('generator', GeneratorParams()), # образующая группы точек кривой
        namedtype.NamedType('order', univ.Integer()),        # порядок группы q
    )


class Signature(univ.Sequence):
    """Подпись (r, s)."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('r', univ.Integer()), # число r
        namedtype.NamedType('s', univ.Integer()), # число s
    )


class KeyInfo(univ.Sequence):
    """Одна последовательность ключа."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', univ.OctetString()), # идентификатор алгоритма
        namedtype.NamedType('keyAlias', char.UTF8String()),   # название ключа
        namedtype.NamedType('publicKey', PublicKey()),        # открытый ключ
        namedtype.NamedType('parameters', SystemParams()),    # параметры криптосистемы
        namedtype.NamedType('signature', Signature()),        # подпись сообщения
    )


class KeySet(univ.SetOf):
    componentType = KeyInfo()  # элемент мн-ва - ключ


class SignatureHeader(univ.Sequence):
    """Заголовок файла подписи."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('keys', KeySet()),            # ножество ключей
        namedtype.NamedType('fileInfo', univ.Sequence()), # параметры файла, не используются
    )


ALG_GOST_SIGN = b'\x80\x06\x07\x00'  # идентификатор алгоритма
