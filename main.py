from dotenv import load_dotenv

from vaultpy.logger import logger
from vaultpy.vault import Vault

load_dotenv()


def main():
    file_path = "/Users/chris/NoCloudZone/vault-py/vault.json"
    logger.info("Starting main function.")
    vault = Vault(file_path)

    # Example usage of CRUD methods
    vault.create("fname", "chris")
    vault.create("lname", "adams")
    vault.update("fname", "Christopher")
    print("All entries:", vault.list_all())
    print("Get 'fname':", vault.get("fname"))

    vault.save()
    logger.info(f"Final vault: {vault.data}")


if __name__ == "__main__":
    main()
