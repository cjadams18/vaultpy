import base64
from os import urandom

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class EncryptionHelper:
    """
    A helper class for encrypting and decrypting data using AES-256 in GCM mode.

    This class provides methods to generate a secure key and perform
    symmetric authenticated encryption and decryption of string data.
    """

    def generate_key(self) -> bytes:
        """
        Generates a secure 32-byte (256-bit) key for AES-256 encryption.

        Returns:
            bytes: A cryptographically strong random key.
        """
        return urandom(32)

    def encrypt(self, plain_text: str, key: bytes, ad: str) -> str:
        """
        Encrypts a plaintext string using AES-256-GCM with associated data.

        This method generates a unique 12-byte Initialization Vector (IV) and a
        16-byte authentication tag. It binds the encrypted data to the provided
        `ad` (additional data) to prevent tampering and password swap attacks.

        Args:
            plain_text (str): The string data to be encrypted.
            key (bytes): The 32-byte AES-256 key.
            ad (str): The additional authenticated data to bind to the ciphertext.

        Returns:
            str: The Base64-encoded string containing the IV, authentication tag,
                 and ciphertext, in that order.
        """
        iv = urandom(12)
        cipher = Cipher(
            algorithm=algorithms.AES(key), mode=modes.GCM(iv), backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(ad.encode())
        cipher_text = encryptor.update(plain_text.encode()) + encryptor.finalize()
        tag = encryptor.tag
        return base64.b64encode(iv + tag + cipher_text).decode()

    def decrypt(self, encrypted: str, key: bytes, ad: str) -> str:
        """
        Decrypts a Base64-encoded string that was encrypted with AES-256-GCM.

        This method decodes the string and extracts the IV, authentication tag, and
        ciphertext. It then uses the `ad` to verify the data's integrity.

        Args:
            encrypted (str): The Base64-encoded encrypted string.
            key (bytes): The 32-byte AES-256 key.
            ad (str): The additional authenticated data to verify against.

        Returns:
            str: The decrypted plaintext string.

        Raises:
            cryptography.exceptions.InvalidTag: If the key, authentication tag, or
                                                additional data is invalid.
        """
        encrypted_bytes = base64.b64decode(encrypted)
        iv = encrypted_bytes[:12]
        tag = encrypted_bytes[12:28]
        cipher_text = encrypted_bytes[28:]
        cipher = Cipher(
            algorithm=algorithms.AES(key),
            mode=modes.GCM(iv, tag),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(ad.encode())
        decrypted_data = decryptor.update(cipher_text) + decryptor.finalize()
        return decrypted_data.decode()
