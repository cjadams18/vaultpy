from os import urandom
from typing import Optional, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class EncryptionHelper:
    def __init__(self):
        self.iterations = 200_000

    def derive_key(
        self, master_password: bytes, salt: Optional[bytes] = None
    ) -> Tuple[bytes, bytes]:
        if salt is None:
            salt = urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.iterations,
            backend=default_backend(),
        )

        key = kdf.derive(master_password)
        return (key, salt)

    def encrypt(
        self,
        plain_text: bytes,
        key: Optional[bytes] = None,
        salt: Optional[bytes] = None,
        master_password: Optional[bytes] = None,
        ad: Optional[bytes] = None,
    ) -> bytes:
        if key is None and master_password is None:
            raise ValueError("Must provide either key or master password")

        if master_password:
            key, salt = self.derive_key(master_password)
        elif salt is None:
            salt = b""

        aesgcm = AESGCM(key)
        iv = urandom(12)
        cipher_text = aesgcm.encrypt(iv, plain_text, ad)

        return salt + iv + cipher_text

    def decrypt(
        self,
        encrypted: bytes,
        key: bytes,
        is_file: Optional[bool] = False,
        ad: Optional[bytes] = None,
    ) -> bytes:
        if is_file:
            iv = encrypted[16:28]
            cipher_text = encrypted[28:]
        else:
            iv = encrypted[:12]
            cipher_text = encrypted[12:]

        aesgcm = AESGCM(key)
        return aesgcm.decrypt(iv, cipher_text, ad)


crypto = EncryptionHelper()
