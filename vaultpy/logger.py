import logging
import os

log_dir = "/Users/chris/NoCloudZone/vault-py/logs"
os.makedirs(log_dir, exist_ok=True)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Info log file handler
info_handler = logging.FileHandler(os.path.join(log_dir, "info.log"))
info_handler.setLevel(logging.INFO)
info_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))

# Error log file handler
error_handler = logging.FileHandler(os.path.join(log_dir, "error.log"))
error_handler.setLevel(logging.ERROR)
error_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))

# Determine environment
env = os.environ.get("VAULT_ENV", "development").lower()

# Console log handler (only for development)
if env == "development":
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)
    console_handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s: %(message)s")
    )

# Avoid duplicate logs if re-running in some environments
if not logger.hasHandlers():
    logger.addHandler(info_handler)
    logger.addHandler(error_handler)
    if env == "development":
        logger.addHandler(console_handler)
else:
    logger.handlers.clear()
    logger.addHandler(info_handler)
    logger.addHandler(error_handler)
    if env == "development":
        logger.addHandler(console_handler)
