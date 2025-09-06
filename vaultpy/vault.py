import json

from vaultpy.logger import logger


class Vault:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.data = self.load()

    def load(self):
        try:
            with open(self.file_path, "r") as file:
                data = json.load(file)
                logger.info("Vault loaded successfully.")
                logger.debug(f"Vault contents: {data}")
                return data
        except FileNotFoundError:
            logger.warning(f"{self.file_path} not found. Starting with an empty vault.")
            return {}
        except Exception as e:
            logger.error(f"Error loading vault: {e}")
            return {}

    def save(self):
        try:
            with open(self.file_path, "w") as file:
                json.dump(self.data, file)
                logger.info("Vault saved successfully.")
        except Exception as e:
            logger.error(f"Error saving vault: {e}")

    def get(self, key: str):
        entry = self.data.get(key)
        if entry is not None:
            logger.info(f"Entry '{key}' retrieved.")
            return entry
        else:
            logger.warning(f"Entry '{key}' not found.")
            return None

    def create(self, key: str, value) -> bool:
        if key in self.data:
            logger.warning(f"Entry '{key}' already exists. Not creating.")
            return False
        self.data[key] = value
        logger.info(f"Entry '{key}' created.")
        return True

    def update(self, key: str, value) -> bool:
        if key not in self.data:
            logger.warning(f"Entry '{key}' not found. Cannot update.")
            return False
        self.data[key] = value
        logger.info(f"Entry '{key}' updated.")
        return True

    def list_all(self):
        logger.info(f"Listing all {len(self.data)} entries.")
        return self.data.copy()
