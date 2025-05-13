# crypto_utils.py
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Menghasilkan nonce + ciphertext.
    AES.MODE_EAX untuk integrity & confidentiality.
    """
    cipher = AES.new(key, AES.MODE_EAX)
    nonce  = cipher.nonce
    ct     = cipher.encrypt(plaintext)
    return nonce + ct

def aes_decrypt(data: bytes, key: bytes) -> bytes:
    """
    Input data = nonce(16 bytes) + ciphertext.
    Mengembalikan plaintext bytes.
    """
    nonce = data[:16]
    ct    = data[16:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt(ct)
