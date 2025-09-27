from vaultpy import db

db.setup_database()

db.create_user("chris", "hello")
