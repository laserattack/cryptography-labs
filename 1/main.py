"""
CLI для работы с RSA + AES-256-CBC + ASN.1.

Использование:
    python3 main.py gen-keys      --bits 2048 --priv rsa_private.pem --pub rsa_public.pem --aes aes_key.bin
    python3 main.py encrypt       -i msg.txt -o msg.enc --pub rsa_public.pem [--aes aes_key.bin] [--alias test]
    python3 main.py decrypt       -i msg.enc -o msg.dec --priv rsa_private.pem
    python3 main.py sign          -i msg.txt -o msg.sig --priv rsa_private.pem [--alias testSign]
    python3 main.py verify        -i msg.txt -s msg.sig
    python3 main.py sign-crc32    -i msg.txt -o msg.sig --priv rsa_private.pem
    python3 main.py verify-crc32  -i msg.txt -s msg.sig

Флаг:
    -v, --verbose   печатать полную ASN.1-структуру
"""

import argparse
import sys

from pyasn1.codec.der import decoder

from keys import (
    generate_keys, load_public_key, load_private_key, load_aes_key,
)
from enc_dec import encrypt_file, decrypt_file
from sign import sign_file, verify_sign
from sign_crc32 import sign_file as sign_crc32, verify_sign as verify_crc32
from asn1_types import EncryptedFileHeader, SignHeader



def dump_asn1_file(path: str, spec_class, label: str) -> None:
    """Читает файл, разбирает ASN.1-заголовок и печатает структуру."""
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


def cmd_gen_keys(args: argparse.Namespace) -> int:
    """Генерация ключей RSA + AES."""
    try:
        generate_keys(args.bits, args.priv, args.pub, args.aes)
    except Exception as e:
        print(f"Ошибка: {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    return 0


def cmd_encrypt(args: argparse.Namespace) -> int:
    """Шифрование файла."""
    try:
        n, e = load_public_key(args.pub)
        aes_key = load_aes_key(args.aes)
        encrypt_file(args.input, args.output, n, e, args.alias, aes_key)

        if args.verbose:
            dump_asn1_file(args.output, EncryptedFileHeader,
                           "ASN.1 заголовок зашифрованного файла")
    except FileNotFoundError as err:
        print(f"Ошибка: файл не найден — {err}", file=sys.stderr)
        return 1
    except Exception as err:
        print(f"Ошибка: {type(err).__name__}: {err}", file=sys.stderr)
        return 1
    return 0


def cmd_decrypt(args: argparse.Namespace) -> int:
    """Расшифрование файла."""
    try:
        if args.verbose:
            dump_asn1_file(args.input, EncryptedFileHeader,
                           "ASN.1 заголовок зашифрованного файла")

        n, d, e = load_private_key(args.priv)
        decrypt_file(args.input, args.output, n, d)
    except FileNotFoundError as err:
        print(f"Ошибка: файл не найден — {err}", file=sys.stderr)
        return 1
    except Exception as err:
        print(f"Ошибка: {type(err).__name__}: {err}", file=sys.stderr)
        return 1
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    """Подписание файла."""
    try:
        n, d, e = load_private_key(args.priv)
        sign_file(args.input, args.output, n, d, e, args.alias)

        if args.verbose:
            dump_asn1_file(args.output, SignHeader,
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
            dump_asn1_file(args.sign, SignHeader,
                           "ASN.1 файл подписи")

        ok = verify_sign(args.input, args.sign)
    except FileNotFoundError as err:
        print(f"Ошибка: файл не найден — {err}", file=sys.stderr)
        return 1
    except Exception as err:
        print(f"Ошибка: {type(err).__name__}: {err}", file=sys.stderr)
        return 1

    return 0 if ok else 2


def cmd_sign_crc32(args: argparse.Namespace) -> int:
    """Подписание файла (RSA-CRC32)."""
    try:
        n, d, e = load_private_key(args.priv)
        sign_crc32(args.input, args.output, n, d, e, args.alias)

        if args.verbose:
            dump_asn1_file(args.output, SignHeader,
                           "ASN.1 файл подписи (CRC32)")
    except FileNotFoundError as err:
        print(f"Ошибка: файл не найден — {err}", file=sys.stderr)
        return 1
    except Exception as err:
        print(f"Ошибка: {type(err).__name__}: {err}", file=sys.stderr)
        return 1
    return 0


def cmd_verify_crc32(args: argparse.Namespace) -> int:
    """Проверка подписи (RSA-CRC32)."""
    try:
        if args.verbose:
            dump_asn1_file(args.sign, SignHeader,
                           "ASN.1 файл подписи (CRC32)")

        ok = verify_crc32(args.input, args.sign)
    except FileNotFoundError as err:
        print(f"Ошибка: файл не найден — {err}", file=sys.stderr)
        return 1
    except Exception as err:
        print(f"Ошибка: {type(err).__name__}: {err}", file=sys.stderr)
        return 1

    return 0 if ok else 2


# Парсер


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='main.py',
        description='RSA + AES-256-CBC + ASN.1',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Примеры:\n"
            "python3 main.py gen-keys --bits 2048\n"
            "python3 main.py encrypt -i msg.txt -o msg.enc --pub rsa_public.pem\n"
            "python3 main.py decrypt -i msg.enc -o msg.dec --priv rsa_private.pem\n"
            "python3 main.py sign    -i msg.txt -o msg.sig --priv rsa_private.pem\n"
            "python3 main.py verify  -i msg.txt -s msg.sig\n"
            "python3 main.py sign-crc32   -i msg.txt -o msg.sig --priv rsa_private.pem\n"
            "python3 main.py verify-crc32 -i msg.txt -s msg.sig\n"
        ),
    )
    sub = parser.add_subparsers(dest='command', required=True,
                                metavar='{gen-keys,encrypt,decrypt,sign,verify,sign-crc32,verify-crc32}')

    # gen-keys
    p = sub.add_parser('gen-keys', help='генерация ключей RSA + AES')
    p.add_argument('--bits', type=int, default=2048,
                   help='размер ключа RSA (по умолчанию 2048)')
    p.add_argument('--priv', default='rsa_private.pem',
                   help='файл закрытого ключа RSA (по умолчанию rsa_private.pem)')
    p.add_argument('--pub', default='rsa_public.pem',
                   help='файл открытого ключа RSA (по умолчанию rsa_public.pem)')
    p.add_argument('--aes', default='aes_key.bin',
                   help='файл AES-ключа (по умолчанию aes_key.bin)')
    p.set_defaults(func=cmd_gen_keys)

    # encrypt
    p = sub.add_parser('encrypt', help='шифрование файла')
    p.add_argument('-i', '--input', required=True,
                   help='входной файл (сообщение)')
    p.add_argument('-o', '--output', required=True,
                   help='выходной зашифрованный файл')
    p.add_argument('--pub', required=True,
                   help='файл открытого ключа RSA')
    p.add_argument('--aes', default=None,
                   help='файл AES-ключа (по умолчанию случайный)')
    p.add_argument('--alias', default='test',
                   help="псевдоним ключа (по умолчанию 'test')")
    p.add_argument('-v', '--verbose', action='store_true',
                   help='печатать полную ASN.1-структуру')
    p.set_defaults(func=cmd_encrypt)

    # decrypt
    p = sub.add_parser('decrypt', help='расшифрование файла')
    p.add_argument('-i', '--input', required=True,
                   help='зашифрованный файл')
    p.add_argument('-o', '--output', required=True,
                   help='выходной расшифрованный файл')
    p.add_argument('--priv', required=True,
                   help='файл закрытого ключа RSA')
    p.add_argument('-v', '--verbose', action='store_true',
                   help='печатать полную ASN.1-структуру')
    p.set_defaults(func=cmd_decrypt)

    # sign
    p = sub.add_parser('sign', help='подписание файла')
    p.add_argument('-i', '--input', required=True,
                   help='файл для подписи')
    p.add_argument('-o', '--output', required=True,
                   help='выходной файл подписи')
    p.add_argument('--priv', required=True,
                   help='файл закрытого ключа RSA')
    p.add_argument('--alias', default='testSign',
                   help="псевдоним ключа (по умолчанию 'testSign')")
    p.add_argument('-v', '--verbose', action='store_true',
                   help='печатать полную ASN.1-структуру')
    p.set_defaults(func=cmd_sign)

    # verify
    p = sub.add_parser('verify', help='проверка подписи')
    p.add_argument('-i', '--input', required=True,
                   help='проверяемый файл')
    p.add_argument('-s', '--sign', required=True,
                   help='файл подписи')
    p.add_argument('-v', '--verbose', action='store_true',
                   help='печатать полную ASN.1-структуру')
    p.set_defaults(func=cmd_verify)

    # sign-crc32
    p = sub.add_parser('sign-crc32', help='подписание файла (RSA-CRC32)')
    p.add_argument('-i', '--input', required=True,
                   help='файл для подписи')
    p.add_argument('-o', '--output', required=True,
                   help='выходной файл подписи')
    p.add_argument('--priv', required=True,
                   help='файл закрытого ключа RSA')
    p.add_argument('--alias', default='testSign',
                   help="псевдоним ключа (по умолчанию 'testSign')")
    p.add_argument('-v', '--verbose', action='store_true',
                   help='печатать полную ASN.1-структуру')
    p.set_defaults(func=cmd_sign_crc32)

    # verify-crc32
    p = sub.add_parser('verify-crc32', help='проверка подписи (RSA-CRC32)')
    p.add_argument('-i', '--input', required=True,
                   help='проверяемый файл')
    p.add_argument('-s', '--sign', required=True,
                   help='файл подписи')
    p.add_argument('-v', '--verbose', action='store_true',
                   help='печатать полную ASN.1-структуру')
    p.set_defaults(func=cmd_verify_crc32)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nПрервано.", file=sys.stderr)
        sys.exit(130)
