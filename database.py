from datetime import datetime

import bcrypt 
import secrets
import sqlite3

from data_models import *
from exceptions import *

# TODO look for a way to use pydantic more directly with the db
# TODO look for a way to use pydantic more directly with the db
# TODO look for a way to use pydantic more directly with the db

# TODO update the Database to reflect the api_key model
# TODO using apiKeys to create logs instead of passwords
# TODO use username and password for apikey management


class Database:
    def initialize(self, db_path):
        self.DB_PATH = db_path
        self.conn = self.connection = sqlite3.connect(self.DB_PATH)
        self.cur = self.cursor = self.conn.cursor()
        self.create_user_table()
        self.create_log_table()

    def commit(self):
        """Shortcut to self.connection.commit()"""
        self.connection.commit()

    def create_user_table(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS User (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username VARCHAR(64) UNIQUE NOT NULL,
                password_hash CHAR(60) NOT NULL
            )
        ''')
        self.commit()

    def create_log_table(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS Log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message TEXT NOT NULL,
                datetime DATETIME NOT NULL,
                user_id INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES User (id)
            )
        ''')
        self.commit()

    def create_apikey_table(self):
        """Creates an ApiKey table

        The permissions `int` entry is a bitwise-flag system.

        See in data_models.py: the AccessPermission's Enum 
        declaration for translation or use the Pydantic model ApiKey's 
        methods to convert between
        the list of Enums and the bitwise-flag int.
        """
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS ApiKey (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                key VARCHAR UNIQUE NOT NULL,
                permissions int NOT NULL,
                FOREIGN KEY (user_id) REFERENCES User (id)
            )
        ''')
        self.commit()

    def create_apikey(self, bytes=16):
        return secrets.token_urlsafe(bytes)

    def select_all_from(self, table):
        self.cursor.execute(f'SELECT * FROM {table}')
        return self.cursor.fetchall()

    def show(self, description = None):
        print("Database:", description if not None else "") 
        print("USERS:")

        users = self.select_all_from("User")
        for user in users:
            print(user)
        
        print("---")
        print("LOGS:")

        logs = self.select_all_from("User")
        for log in logs:
            print(log)

    def create_password_hash(self, password):
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    def verify_password(self, username, password) -> bool:
        self.cursor.execute(
                'SELECT password_hash FROM User WHERE username=?', (username,))
        # SELECT password_hash returns only the hash and no other data
        stored_hash = self.cursor.fetchone()[0]
        if stored_hash:
            return bcrypt.checkpw(password.encode(), stored_hash)
        return False

    def insert_user(self, username, password):
        password_hash = self.create_password_hash(password)

        self.cursor.execute('''
            INSERT INTO User (username, password_hash)
            VALUES (?, ?)
        ''', (username, password_hash))

        self.commit()

    def delete_user(self, username, password) -> Exception:
        """Deletes a user and all their logs"""
        if not self.verify_password(username, password):
            return IncorrectPassword
        
        user_id = self.get_user_id(username)
        
        result = self.delete_all_user_logs(user_id, username, password)
        if result is not Ok:
            return DeletionFailed


        self.cursor.execute(
                'DELETE FROM User WHERE username = ?', (username,))

        self.commit()
        return Ok

    def get_user_id(self, username) -> int | None:
        self.cur.execute(
                "SELECT id FROM User WHERE username = ?", (username,))
        wrapped_user_id = self.cur.fetchone()
        if wrapped_user_id is not None:
            return wrapped_user_id[0]
        return None

    def insert_log(self, username, password, message) -> Exception:
        if not self.verify_password(username, password):
            return IncorrectPassword

        user_id = self.get_user_id(username)

        self.cursor.execute('''
            INSERT INTO Log (user_id, message, datetime)
            VALUES (?, ?, ?)
        ''', (user_id, message, datetime.now()))

        self.commit()
        return Ok

    def delete_all_user_logs(
            self, user_id: int, username: str, password: str) -> Exception:
        """Deletes all logs for a given user"""
        if not self.verify_password(username, password):
            return IncorrectPassword

        self.cur.execute(
                'DELETE FROM Log WHERE user_id = ?', (user_id,))

        self.commit()
        return Ok

    def test(self, users: int = 1, logs: int = 1) -> Exception:
        print("Testing tmp `Database` in memory")
        test_username = 'john'
        test_password = 'password'

        # Database is empty
        assert len(self.select_all_from("User")) == 0
        assert len(self.select_all_from("Log")) == 0
        print("1: empty database... ✔")

        self.insert_user(test_username, test_password)
        
        # Datebase has 1 user
        assert len(self.select_all_from("User")) == 1
        print("2: one user in db... ✔")

        # verify_password works as expected
        assert self.verify_password(test_username, test_password)
        assert not self.verify_password(test_username, "incorrect_password")
        print("3: password verification... ✔")

        # TODO test log insert and deletion
        
        message = "This is a test log message 124459879827305928735908"
        self.insert_log(test_username, test_password, message)

        # There is 1 log in the Log table...
        assert len(self.select_all_from("Log")) == 1
        print("4: one log in db... ✔")

        self.delete_user(test_username, test_password)

        # User and their logs deletion confirmed
        assert len(self.select_all_from("User")) == 0
        assert len(self.select_all_from("Log")) == 0
        print("5: user and user logs deletion... ✔")

        print("6: empty database... ✔")
        print("All `Database` tests passed... ✔")

        return Ok


if __name__ == "__main__":
    print("Testing basic impl of `Database`")
    db = Database()
    db.initialize(":memory:")
    db.test()

