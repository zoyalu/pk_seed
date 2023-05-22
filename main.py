import getpass
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Protocol.KDF import scrypt
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes

def decrypt(text, key):
    text_parts = text.split(':')
    iv = bytes.fromhex(text_parts[0])
    encrypted_text = bytes.fromhex(text_parts[1])
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted_text = unpad(cipher.decrypt(encrypted_text), AES.block_size).decode('utf-8')
    return decrypted_text

def get_encryption_key(password):
    return scrypt(password, 'salt', 32, N=16384, r=8, p=1)

def get_private_key_and_address(mnemonic):
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
    bip_obj_mst = Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM)
    bip_obj_acc = bip_obj_mst.Purpose().Coin().Account(0)
    bip_obj_chain = bip_obj_acc.Change(Bip44Changes.CHAIN_EXT)
    bip_obj_addr = bip_obj_chain.AddressIndex(0)
    private_key = bip_obj_addr.PrivateKey().Raw().ToHex()
    address = bip_obj_addr.PublicKey().ToAddress()
    return private_key, address

password = getpass.getpass('Введите пароль для дешифрования: ')
key = get_encryption_key(password)
line_number = input('Введите номер строки для расшифровки (оставьте пустым для расшифровки всех строк): ')

with open('mnemonics.txt', 'r') as file:
    encrypted_mnemonics = file.read().splitlines()

if line_number:
    line_number = int(line_number) - 1  # Список номеров строк, которые нужно расшифровать (нумерация с 1)
    encrypted_mnemonics = [encrypted_mnemonics[line_number]]

for i, encrypted_mnemonic in enumerate(encrypted_mnemonics):
    mnemonic = decrypt(encrypted_mnemonic, key)
    private_key, address = get_private_key_and_address(mnemonic)
    print('Line:', i+1)
    print('Private key:', private_key)
    print('Address:', address)
