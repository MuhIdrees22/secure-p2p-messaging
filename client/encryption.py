# AES encryption and decryption module

import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

BLOCK_SIZE = AES.block_size  # 16 bytes


def _shared_secret_to_bytes(shared_secret):
    """
    Convert the shared secret into bytes.

    Accepts:
    - int   (most likely from Diffie-Hellman)
    - str
    - bytes
    """
    if isinstance(shared_secret, int):
        length = max(1, (shared_secret.bit_length() + 7) // 8)
        return shared_secret.to_bytes(length, byteorder="big")
    elif isinstance(shared_secret, bytes):
        return shared_secret
    elif isinstance(shared_secret, str):
        return shared_secret.encode("utf-8")
    else:
        raise TypeError("shared_secret must be int, str, or bytes")


def derive_aes_key(shared_secret):
    """
    Derive a 32-byte AES-256 key from the Diffie-Hellman shared secret
    using SHA-256.
    """
    secret_bytes = _shared_secret_to_bytes(shared_secret)
    return hashlib.sha256(secret_bytes).digest()


def encrypt_message(plaintext, shared_secret):
    """
    Encrypt a plaintext string using AES-256-CBC.

    Returns:
        A base64 string containing IV + ciphertext
    """
    if not isinstance(plaintext, str):
        raise TypeError("plaintext must be a string")

    key = derive_aes_key(shared_secret)
    iv = get_random_bytes(16)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode("utf-8"), BLOCK_SIZE))

    payload = iv + ciphertext
    return base64.b64encode(payload).decode("utf-8")


def decrypt_message(encrypted_payload, shared_secret):
    """
    Decrypt a base64 string produced by encrypt_message().

    Returns:
        The original plaintext string
    """
    if not isinstance(encrypted_payload, str):
        raise TypeError("encrypted_payload must be a string")

    raw_data = base64.b64decode(encrypted_payload)

    if len(raw_data) < 16:
        raise ValueError("Invalid encrypted payload")

    iv = raw_data[:16]
    ciphertext = raw_data[16:]

    key = derive_aes_key(shared_secret)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)

    return plaintext.decode("utf-8")


if __name__ == "__main__":
    # simple self-test for Member 3
    test_shared_secret = 123456789
    test_message = "Hello, this is a secure test message."

    encrypted = encrypt_message(test_message, test_shared_secret)
    decrypted = decrypt_message(encrypted, test_shared_secret)

    print("Original :", test_message)
    print("Encrypted:", encrypted)
    print("Decrypted:", decrypted)