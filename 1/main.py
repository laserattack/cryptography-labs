"""
CLI для работы с RSA + AES-256-CBC + ASN.1.

Использование:
    python3 main.py gen-keys   --bits 2048 --priv rsa_private.pem --pub rsa_public.pem --aes aes_key.bin
    python3 main.py encrypt    -i msg.txt -o msg.enc --pub rsa_public.pem [--aes aes_key.bin] [--alias test]
    python3 main.py decrypt    -i msg.enc -o msg.dec --priv rsa_private.pem
    python3 main.py sign       -i msg.txt -o msg.sig --priv rsa_private.pem [--alias testSign]
    python3 main.py verify     -i msg.txt -s msg.sig
"""

import argparse
import sys

from keys import (
    generate_keys, load_public_key, load_private_key, load_aes_key,
)
from enc_dec import encrypt_file, decrypt_file
from sign import sign_file, verify_sign



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
        ok = verify_sign(args.input, args.sign)
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
        ),
    )
    sub = parser.add_subparsers(dest='command', required=True,
                                metavar='{gen-keys,encrypt,decrypt,sign,verify}')

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
    p.set_defaults(func=cmd_encrypt)

    # decrypt
    p = sub.add_parser('decrypt', help='расшифрование файла')
    p.add_argument('-i', '--input', required=True,
                   help='зашифрованный файл')
    p.add_argument('-o', '--output', required=True,
                   help='выходной расшифрованный файл')
    p.add_argument('--priv', required=True,
                   help='файл закрытого ключа RSA')
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
    p.set_defaults(func=cmd_sign)

    # verify
    p = sub.add_parser('verify', help='проверка подписи')
    p.add_argument('-i', '--input', required=True,
                   help='проверяемый файл')
    p.add_argument('-s', '--sign', required=True,
                   help='файл подписи')
    p.set_defaults(func=cmd_verify)

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
