import bcrypt 
import secrets
import sqlite3

from common import *

# TODO look for a way to use pydantic more directly with the db

# TODO update the Database to reflect the api_key model
# TODO using apiKeys to create logs instead of passwords
# TODO use username and password for apikey management


# TODO try to make a decorator that auto does self.verify_password on a method

class Database:
    def initialize(self, db_path):
        self.DB_PATH = db_path
        self.conn = self.connection = sqlite3.connect(self.DB_PATH)
        self.cur = self.cursor = self.conn.cursor()
        self.create_user_table()
        self.create_log_table()
        self.create_apikey_table()

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
        # TODO change user_id to apikey_id to track which apikey created the log
        # and the apikey can be reversed to a user_id easily as well.
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
                key VARCHAR UNIQUE NOT NULL,
                permissions int NOT NULL,
                user_id INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES User (id)
            )
        ''')
        self.commit()

    def delete_apikey(self, username: str, password: str, key: str) -> Exception:
        if not self.verify_password(username, password):
            return IncorrectPassword

        self.cursor.execute(
                'DELETE FROM ApiKey WHERE key = ?', (key,))
        self.commit()
        return Ok

    def create_apikey(
            self, username: str, password: str, 
            permissions: list[AccessPermission] | int) -> ApiKey | Exception:

        if not self.verify_password(username, password):
            return IncorrectPassword

        # make sure you have a permissions int flag first
        if type(permissions) == list:
            permissions = flag_from_permissions_list(permissions)

        key = self.generate_apikey_str(permissions)
        self.cur.execute('SELECT id FROM User WHERE username = ?', (username,))
        user_id = self.cur.fetchone()[0]

        self.cur.execute('''
            INSERT INTO ApiKey (key, permissions, user_id)
            VALUES (?, ?, ?)
        ''', (key, permissions, user_id))
        self.commit()
        # get the API key back from the database for confirmation of INSERT
        self.cur.execute('SELECT * FROM ApiKey WHERE key = ?', (key,))
        return self.cur.fetchone()


    def generate_apikey_str(
            self, permissions: int | list[AccessPermission]) -> str:
        """Higher the byte count the higher the security, but the slower TX/RX\n
        permissions effect the security_level:
        1: 16 bytes long for WRITE_ONLY, 
        2: 32 (16*2) bytes for READ, 
        3: 48 (16*3) for DELETE
        4: 64 (16*4) bytes long for ADMIN (ADMIN=all_permissions_a_user_has)
        """

        # make sure you have a permissions int flag first
        if type(permissions) == list:
            permissions = flag_from_permissions_list(permissions)

        security_level = 1
        if permissions & AccessPermission.READ.value:
            security_level = 2
        if permissions & AccessPermission.DELETE.value:
            security_level = 3
        if permissions & AccessPermission.ADMIN.value:
            security_level = 4

        return secrets.token_urlsafe(16 * security_level)


    def select_all_from(self, table_name: str) -> list[tuple]:
        self.cursor.execute(f'SELECT * FROM {table_name}')
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

    def insert_user(self, username, password) -> tuple | None:
        password_hash = self.create_password_hash(password)

        self.cursor.execute('''
            INSERT INTO User (username, password_hash)
            VALUES (?, ?)
        ''', (username, password_hash))

        self.commit()
        self.cur.execute(
                'SELECT * FROM User WHERE username=?', (username,))
        return self.cur.fetchone()

    def delete_user(self, username, password) -> Exception:
        """Deletes a user and all their logs"""
        if not self.verify_password(username, password):
            return IncorrectPassword
        
        user_id = self.get_user_id(username)

        # delete user's logs
        self.cur.execute(
                'DELETE FROM Log WHERE user_id = ?', (user_id,))
        # delete user's apikeys
        self.cur.execute(
                'DELETE FROM ApiKey WHERE user_id = ?', (user_id,))
        # delete user
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


    def test(self, users: int = 1, logs: int = 1) -> Exception:
        print("Testing tmp `Database` in memory")
        test_username = 'john'
        test_password = 'password'

        # Database is empty
        assert len(self.select_all_from("User")) == 0
        assert len(self.select_all_from("Log")) == 0
        print("1: empty database... ✔")

        print(self.insert_user(test_username, test_password))
        
        # Datebase has 1 user
        assert len(self.select_all_from("User")) == 1
        print("2: one user in db... ✔")

        # verify_password works as expected
        assert self.verify_password(test_username, test_password)
        assert not self.verify_password(test_username, "incorrect_password")
        print("3: password verification... ✔")

        # TODO create an apikey CRUD management system (without READ or UPDATE)
        # as UPDATE would cause the security level to change
        # and READ would mean that if an user was compromised then existing keys
        # could be discovered easily by a hacker
        # but if a hacker is forced to create a new API key then it is easy to
        # undo their actions after the fact (with good database history systems)

        # CREATE (only show the user an API key once on creation!

        permissions = [ AccessPermission.WRITE ]
        new_key = self.create_apikey(test_username, test_password, permissions)

        print(new_key)

        permissions = 3 # WRITE & READ FLAG
        new_key = self.create_apikey(test_username, test_password, permissions)
        print(new_key)
        assert len(self.select_all_from("ApiKey")) == 2 # haven't deleted them yet
        print("4: create api keys... ✔")

        key = new_key[1]
        self.delete_apikey(test_username, test_password, key)

        assert len(self.select_all_from("ApiKey")) == 1 # haven't deleted them yet
        print("4: delete api key... ✔")


        # TODO change log insert to use an apikey with WRITE permissions
        message = "This is a test log message 124459879827305928735908"
        self.insert_log(test_username, test_password, message)

        # There is 1 log in the Log table...
        assert len(self.select_all_from("Log")) == 1
        print("5: one log in db... ✔")

        self.delete_user(test_username, test_password)

        # User and their logs deletion confirmed
        assert len(self.select_all_from("ApiKey")) == 0 
        assert len(self.select_all_from("User")) == 0
        assert len(self.select_all_from("Log")) == 0
        print("6: user and user logs deletion... ✔")

        print("6: empty database... ✔")
        print("All `Database` tests passed... ✔")

        return Ok


if __name__ == "__main__":
    print("Testing basic impl of `Database`")
    db = Database()
    db.initialize(":memory:")
    db.test()

