# Vault-py

## Functionality to start:

1) ability to load passwords from a file into memory as dictionary, 
2) retrieve and display passwords, 
3) edit existing, 
4) add new, 
5) save updating dictionary back to file, 
6) encrypt/decrypt the file on startup and shutdown.

## Later..

1) user login with master password
2) master password will be hashed and salted, stored in local db
3) master password will also be used in combination with another salt (saved to vault file), to decrypt the data in file
4) how should I do a user login? I think I want to start with a TUI if possible, then move from there
5) Need a timeout that closes app after so many minutes for security

## Even later...

1) research how 1password makes watchtower (scan known hash tables for bad passwords)
2) some kind of import/export of password db (as secure JSON I think it's called?)
3) desktop application