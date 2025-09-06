# Copilot Instructions for vault-py

## Project Overview

-   `vault-py` is a Python-based password vault CLI app.
-   Core functionality: load, display, edit, add, and save passwords as a dictionary, with plans for encryption and user authentication.
-   Passwords are stored in a JSON file (default: `passwords.json`), loaded into memory, and manipulated as a Python dict.

## Architecture & Key Files

-   `main.py`: Main entry point. Handles loading/saving the vault, and basic CRUD operations on the password dictionary.
-   `logger.py`: Centralized logging configuration. All modules should import `logger` from here for consistent logging. Logging is environment-aware (see `.env`).
-   `.env`: Stores environment variables (e.g., `VAULT_ENV`). Loaded at the top of `main.py` using `python-dotenv`.
-   `logs/`: Directory for log files (`info.log`, `error.log`).

## Patterns & Conventions

-   All logging must use `from logger import logger`.
-   Environment variables are loaded once at the top of `main.py` via `load_dotenv()`.
-   Console logging is enabled only if `VAULT_ENV=development`.
-   Password data is always loaded/saved as a dict using the `json` module.
-   No global variables: pass the vault dict explicitly between functions.

## Developer Workflows

-   To run: `python main.py`
-   To set environment: edit `.env` (e.g., `VAULT_ENV=production`)
-   To add dependencies: use pip and update requirements as needed.
-   Logging output: see `logs/info.log`, `logs/error.log`, and console (in development).

## Extending Functionality

-   For new features (e.g., encryption, user login), add new modules and import `logger` for logging.
-   Follow the pattern of loading configuration and environment variables at the top of the entry point.
-   Keep all sensitive data out of version control (add `.env`, `logs/`, and any future secrets to `.gitignore`).

## Example Usage

```python
from logger import logger
logger.info("This is a log message.")
```

## References

-   See `README.md` for planned features and roadmap.
-   See `main.py` and `logger.py` for current implementation patterns.
