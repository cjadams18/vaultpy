import json
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def load_vault(file_path: str):
    try:
        with open(file_path, "r") as file:
            vault = json.load(file)
            logger.info("Vault loaded successfully.")
            logger.debug(f"Vault contents: {vault}")
            return vault
    except FileNotFoundError:
        logger.warning(f"{file_path} not found. Starting with an empty vault.")
        return {}
    except Exception as e:
        logger.error(f"Error loading vault: {e}")
        return {}


def save_vault(vault, file_path: str) -> None:
    try:
        with open(file_path, "w") as file:
            json.dump(vault, file)
            logger.info("Vault saved successfully.")
    except Exception as e:
        logger.error(f"Error saving vault: {e}")


def main():
    file_path = "/Users/chris/NoCloudZone/vault-py/passwords.json"
    logger.info("Starting main function.")
    vault = load_vault(file_path)
    # Example modification to vault
    vault["fname"] = "chris"
    vault["lname"] = "adams"
    save_vault(vault, file_path)
    logger.info(f"Final vault: {vault}")


if __name__ == "__main__":
    main()
