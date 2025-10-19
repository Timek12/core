from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import os

class CryptoService:
    def __init__(self):
        pass

    @staticmethod
    def hkdf_derive(key: bytes, salt: bytes, info: bytes = b"123456789", length: int = 32) -> bytes:
        hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
        return hkdf.derive(key)

    @staticmethod
    def aesgcm_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)
        return nonce, ct

    @staticmethod
    def aesgcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, associated_data=None)