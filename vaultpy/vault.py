import json
from typing import Optional

from vaultpy.encryption_helper import crypto
from vaultpy.logger import logger


class Vault:
    def __init__(self, file_path: str, username: bytes):
        self.file_path: str = file_path
        self.username = username
        self.data: dict[str, dict] = {}
        self.encryption_key: Optional[bytes] = None
        self.salt: Optional[bytes] = None

    def load(self, master_password: bytes):
        try:
            with open(self.file_path, "rb") as file:
                file_content = file.read()

            self.salt = file_content[:16]
            self.encryption_key, _ = crypto.derive_key(master_password, self.salt)

            json_bytes = crypto.decrypt(
                encrypted=file_content,
                key=self.encryption_key,
                is_file=True,
                ad=self.username,
            )

            self.data = json.loads(json_bytes.decode())
        except FileNotFoundError:
            logger.warning(f"{self.file_path} not found. Starting with an empty vault.")
            self.data = {}
        except Exception as e:
            raise Exception(f"Error loading vault: {e}")

    def save(self):
        if self.encryption_key is None or self.salt is None:
            raise ValueError("Vault encryption key and salt must be initialized first")

        try:
            json_bytes = json.dumps(self.data).encode()
            file_content = crypto.encrypt(
                plain_text=json_bytes,
                key=self.encryption_key,
                salt=self.salt,
                ad=self.username,
            )

            with open(self.file_path, "wb") as file:
                file.write(file_content)
                logger.info("Vault saved successfully.")
        except Exception as e:
            logger.error(f"Error saving vault: {e}")

    def get(self, key: str):
        if self.encryption_key is None or self.salt is None:
            raise ValueError("Vault encryption key and salt must be initialized first")

        entry = self.data.get(key)
        if entry is not None:
            crypto.decrypt(entry, self.encryption_key, key)
            logger.info(f"Entry '{key}' retrieved.")
            return entry
        else:
            logger.warning(f"Entry '{key}' not found.")
            return None

    def create(self, key: str, value) -> bool:
        if self.encryption_key is None or self.salt is None:
            raise ValueError("Vault encryption key and salt must be initialized first")

        if key in self.data:
            logger.warning(f"Entry '{key}' already exists. Not creating.")
            return False
        # self.data[key] = crypto.encrypt(value, self.encryption_key, key)
        self.data[key] = value
        logger.info(f"Entry '{key}' created.")
        return True

    def update(self, key: str, value) -> bool:
        if self.encryption_key is None or self.salt is None:
            raise ValueError("Vault encryption key and salt must be initialized first")

        if key not in self.data:
            logger.warning(f"Entry '{key}' not found. Cannot update.")
            return False
        self.data[key] = crypto.encrypt(value, self.encryption_key, key)
        logger.info(f"Entry '{key}' updated.")
        return True

    def list_all(self):
        logger.info(f"Listing all {len(self.data)} entries.")
        return self.data.copy()
