import os
import sqlite3

from vaultpy.encryption_helper import crypto
from vaultpy.logger import logger


def setup_database():
    """
    Connects to or creates the SQLite database file and sets up the
    'user' table if it doesn't already exist.
    """
    try:
        conn = sqlite3.connect("password_manager.db")
        logger.info("Database connection established successfully.")

        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                file_path TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # Commit the changes to the database
        conn.commit()
        logger.info("Table 'user' created or already exists.")
    except sqlite3.Error as e:
        logger.error(f"An error occurred: {e}")
    finally:
        # Close the connection
        if conn:
            conn.close()
            logger.info("Database connection closed.")


def get_db_connection():
    """Returns a connection to the SQLite database."""
    conn = sqlite3.connect("password_manager.db")
    conn.row_factory = sqlite3.Row
    return conn


def is_existing_user(username: str) -> bool:
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT * FROM user WHERE username = ?
        """,
        (username,),
    )

    row = cursor.fetchone()
    return row is not None


def create_user(username: str, master_password: str) -> bool:
    """
    Registers a new user and creates their encrypted vault file.

    Returns True on success, False on failure.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        if is_existing_user(username):
            logger.error(f"Username '{username}' already exists")
            return False

        current_directory = os.getcwd()
        filename = f"{username}.vault"
        vault_file_path = os.path.join(current_directory, filename)
        initial_vault = b'{"google.com":{"site":"google.com","username":"chris","password":"password"}}'  # TODO

        file_content = crypto.encrypt(
            plain_text=initial_vault,
            master_password=master_password.encode(),
            ad=username.encode(),
        )

        with open(vault_file_path, "wb") as f:
            f.write(file_content)

        hashed_password, salt = crypto.derive_key(master_password.encode())

        cursor.execute(
            """
            INSERT INTO user (username, hash, salt, file_path)
            VALUES (?, ?, ?, ?);
            """,
            (username, hashed_password.hex(), salt.hex(), vault_file_path),
        )

        conn.commit()
        logger.info(f"User '{username}' created successfully.")

        return True
    except sqlite3.IntegrityError:
        logger.error(f"Error: Username '{username}' already exists.")
        return False
    finally:
        conn.close()


def authenticate_user(username: str, master_password: str) -> str | None:
    """
    Authenticates a user and returns the path to their vault file on success.

    Returns the file path or None on failure.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            "SELECT hash, salt, file_path FROM user WHERE username = ?", (username,)
        )

        user_record = cursor.fetchone()
        if not user_record:
            logger.warning("Authentication failed: User not found.")
            return None

        stored_hash = bytes.fromhex(user_record["hash"])
        stored_salt = bytes.fromhex(user_record["salt"])
        file_path = user_record["file_path"]

        # Hash the entered password with the stored salt
        entered_hash, _ = crypto.derive_key(master_password.encode(), stored_salt)
        if entered_hash != stored_hash:
            logger.warning("Authentication failed: Incorrect password.")
            return None

        logger.info(f"Authentication successful for user '{username}'.")
        return file_path
    finally:
        conn.close()


if __name__ == "__main__":
    setup_database()
