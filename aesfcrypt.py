#!/usr/bin/python3
import argparse
import hashlib
from Crypto.Cipher import AES
from Crypto.Util import Counter


def _derive_key(password, size, salt='default salt'):
    if type(password) is str:
        password = bytes(password, 'utf8')
    if type(salt) is str:
        salt = bytes(salt, 'utf8')
    return hashlib.pbkdf2_hmac(hash_name='sha256', password=password, salt=salt, iterations=250, dklen=size)


def _derive_aes_key_iv(password):
    key = _derive_key(password, 32, 'my key salt')
    iv = _derive_key(password, AES.block_size, 'my iv salt')
    return key, iv


def encrypt(password, plaintext):
    key, iv = _derive_aes_key_iv(password)
    iv_int = int(iv.hex(), 16) 
    ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)
    ciphertext = aes.encrypt(plaintext)
    return ciphertext


def decrypt(password, ciphertext):
    key, iv = _derive_aes_key_iv(password)
    iv_int = int(iv.hex(), 16) 
    ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)
    plaintext = aes.decrypt(ciphertext)
    return plaintext


def encrypt_file(source, dest, password):
    with open(source, 'rb') as file:
        data = file.read()
    p_data = encrypt(password, data)
    with open(dest, 'wb') as file:
        file.write(p_data)


def decrypt_file(source, dest, password):
    with open(source, 'rb') as file:
        data = file.read()
    p_data = decrypt(password, data)
    with open(dest, 'wb') as file:
        file.write(p_data)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='aesfcrypt',
        description='AES file encryptor and decryptor',
        epilog=''
    )
    #parser.add_argument('-b64', '--base64', action='store_true')
    parser.add_argument('-a', '--action', choices=('encrypt', 'decrypt'), default='encrypt',
        help='encrypt or decrypt')
    parser.add_argument('-i', '--input', type=argparse.FileType(mode='rb'), 
        required=True, help='input file name', metavar='INPUT_FILENAME')
    parser.add_argument('-o', '--output', type=argparse.FileType(mode='wb'),
        required=True, help='output file name', metavar='OUTPUT_FILENAME')
    parser.add_argument('-p', '--password', type=str, required=True,
        help='encryption/decryption password')
    
    args = parser.parse_args()
    
    data = args.input.read()
    args.input.close()
    f = encrypt if args.action == 'encrypt' else decrypt
    new_data = f(args.password, data)
    args.output.write(new_data)
    args.output.close()
