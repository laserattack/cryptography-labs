"""
CLI для работы с ГОСТ Р 34.10-2018.

Использование:
    python3 main.py gen-keys   [-o key.txt]
    python3 main.py sign       -i msg.txt -o msg.sig [--priv key.txt]
    python3 main.py verify     -i msg.txt -s msg.sig

Флаг:
    -v, --verbose   печатать ASN.1-структуру
"""

import argparse
import sys

from pyasn1.codec.der import decoder

from ec_math import ECPoint, scalar_mul
from gost_sign import (
    generate_keypair, sign_file, verify_file,
    P, a, p,
)
from asn1_types import SignatureHeader


def dump_asn1_file(path: str, spec_class, label: str) -> None:
    """Читает файл, разбирает ASN.1-структуру и печатает её."""
    with open(path, 'rb') as f:
        data = f.read()
    header, remaining = decoder.decode(data, asn1Spec=spec_class())

    print()
    print(f"{label}")
    print(f"Файл: {path}, размер: {len(data)} байт")
    print(f"Заголовок: {len(data) - len(remaining)} байт, "
          f"остаток: {len(remaining)} байт")
    print(f"Hex (первые 64 байта): {data[:64].hex()}"
          + ("..." if len(data) > 64 else ""))
    print(header.prettyPrint())


# ============================================================
#  Команды
# ============================================================

def cmd_gen_keys(args: argparse.Namespace) -> int:
    """Генерация ключевой пары, сохранение d в файл."""
    d, Q = generate_keypair()

    # сохраняем d в файл
    with open(args.output, 'w') as f:
        f.write(str(d))

    print(f"Секретный ключ сохранён: {args.output}")
    print(f"d = {d}")
    print(f"Q = ({Q.x}, {Q.y})")
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    """Подпись файла."""
    # 1. Ключ: из файла или сгенерированный
    if args.priv:
        with open(args.priv) as f:
            d = int(f.read().strip())
        Q = scalar_mul(d, P, a, p)
        print(f"Использован ключ из {args.priv}")
    else:
        d, Q = generate_keypair()
        print(f"Сгенерирован новый ключ:")
        print(f"  d = {d}")
        print(f"  Q = ({Q.x}, {Q.y})")

    # 2. Подпись
    try:
        sign_file(args.input, args.output, d, Q, args.alias)
        if args.verbose:
            dump_asn1_file(args.output, SignatureHeader,
                           "ASN.1 файл подписи")
    except FileNotFoundError as err:
        print(f"Ошибка: файл не найден — {err}", file=sys.stderr)
        return 1
    except Exception as err:
        print(f"Ошибка: {type(err).__name__}: {err}", file=sys.stderr)
        return 1
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Проверка подписи."""
    try:
        if args.verbose:
            dump_asn1_file(args.sign, SignatureHeader,
                           "ASN.1 файл подписи")

        ok = verify_file(args.sign, args.input)
        print("Подпись верна" if ok else "Подпись неверна")
    except FileNotFoundError as err:
        print(f"Ошибка: файл не найден — {err}", file=sys.stderr)
        return 1
    except Exception as err:
        print(f"Ошибка: {type(err).__name__}: {err}", file=sys.stderr)
        return 1

    return 0 if ok else 2


# ============================================================
#  Парсер
# ============================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='main.py',
        description='ГОСТ Р 34.10-2018 — ЭЦП на эллиптических кривых',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Примеры:\n"
            "  python3 main.py gen-keys\n"
            "  python3 main.py gen-keys -o mykey.txt\n"
            "  python3 main.py sign   -i msg.txt -o msg.sig\n"
            "  python3 main.py sign   -i msg.txt -o msg.sig --priv mykey.txt\n"
            "  python3 main.py verify -i msg.txt -s msg.sig\n"
            "  python3 main.py verify -i msg.txt -s msg.sig -v\n"
        ),
    )
    sub = parser.add_subparsers(dest='command', required=True,
                                metavar='{gen-keys,sign,verify}')

    # gen-keys
    p = sub.add_parser('gen-keys', help='генерация ключевой пары')
    p.add_argument('-o', '--output', default='key.txt',
                   help='файл для секретного ключа (по умолчанию key.txt)')
    p.set_defaults(func=cmd_gen_keys)

    # sign
    p = sub.add_parser('sign', help='подписать файл')
    p.add_argument('-i', '--input', required=True,
                   help='файл для подписи')
    p.add_argument('-o', '--output', required=True,
                   help='выходной файл подписи (.sig)')
    p.add_argument('--priv', default=None,
                   help='файл с секретным ключом d (если не указан — '
                        'генерируется новый)')
    p.add_argument('--alias', default='gostSignKey',
                   help="псевдоним ключа (по умолчанию 'gostSignKey')")
    p.add_argument('-v', '--verbose', action='store_true',
                   help='печатать ASN.1-структуру')
    p.set_defaults(func=cmd_sign)

    # verify
    p = sub.add_parser('verify', help='проверить подпись')
    p.add_argument('-i', '--input', required=True,
                   help='проверяемый файл')
    p.add_argument('-s', '--sign', required=True,
                   help='файл подписи (.sig)')
    p.add_argument('-v', '--verbose', action='store_true',
                   help='печатать ASN.1-структуру')
    p.set_defaults(func=cmd_verify)

    return parser



# echo "Test message" > msg.txt
# python3 main.py gen-keys
# python3 main.py sign -i msg.txt -o msg.sig --priv key.txt
# python3 main.py verify -i msg.txt -s msg.sig
def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("Прервано.", file=sys.stderr)
        sys.exit(130)
