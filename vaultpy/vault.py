import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vaultpy.db import hash_master_password
from vaultpy.encryption_helper import EncryptionHelper
from vaultpy.logger import logger


class Vault:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.data = {}
        self.encryption_helper = EncryptionHelper()
        self.encryption_key: str | None = None
        self.salt: str | None = None

    def load(self, master_password: str):
        try:
            with open(self.file_path, "rb") as file:
                file_content = file.read()

            self.salt = file_content[:16]
            self.encryption_key = hash_master_password(master_password, self.salt)

            iv = file_content[16:28]
            encrypted_vault_with_tag = file_content[28:]

            aesgcm = AESGCM(self.encryption_key)
            vault_json_bytes = aesgcm.decrypt(iv, encrypted_vault_with_tag, None)

            self.data = json.loads(vault_json_bytes.decode())
        except FileNotFoundError:
            logger.warning(f"{self.file_path} not found. Starting with an empty vault.")
            self.data = {}
        except InvalidTag:
            raise Exception(
                "Decryption failed. Master password may be incorrect or vault file is corrupted"
            )
        except Exception as e:
            raise Exception(f"Error loading vault: {e}")

    def save(self):
        try:
            aesgcm = AESGCM(self.encryption_key)
            iv = os.urandom(12)

            encrypted_vault = aesgcm.encrypt(iv, json.dumps(self.data).encode(), None)
            file_content = self.salt + iv + encrypted_vault

            with open(self.file_path, "wb") as file:
                file.write(file_content)
                logger.info("Vault saved successfully.")
        except Exception as e:
            logger.error(f"Error saving vault: {e}")

    def get(self, key: str):
        entry = self.data.get(key)
        if entry is not None:
            self.encryption_helper.decrypt(entry, self.encryption_key, key)
            logger.info(f"Entry '{key}' retrieved.")
            return entry
        else:
            logger.warning(f"Entry '{key}' not found.")
            return None

    def create(self, key: str, value) -> bool:
        if key in self.data:
            logger.warning(f"Entry '{key}' already exists. Not creating.")
            return False
        self.data[key] = self.encryption_helper.encrypt(value, self.encryption_key, key)
        logger.info(f"Entry '{key}' created.")
        return True

    def update(self, key: str, value) -> bool:
        if key not in self.data:
            logger.warning(f"Entry '{key}' not found. Cannot update.")
            return False
        self.data[key] = self.encryption_helper.encrypt(value, self.encryption_key, key)
        logger.info(f"Entry '{key}' updated.")
        return True

    def list_all(self):
        logger.info(f"Listing all {len(self.data)} entries.")
        return self.data.copy()
