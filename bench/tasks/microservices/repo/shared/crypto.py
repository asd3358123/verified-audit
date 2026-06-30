from Crypto.Cipher import AES

_KEY = b"0123456789abcdef"
_IV = b"0000000000000000"


def encrypt(plaintext):
    cipher = AES.new(_KEY, AES.MODE_CBC, _IV)
    pad = 16 - len(plaintext) % 16
    data = plaintext + bytes([pad]) * pad
    return cipher.encrypt(data)
