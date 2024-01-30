import bcrypt 
import secrets
import sqlite3

from common import *

# NOTE: keep side-effect functions seperate from read_only 
#       and other pure functions

# TODO use username and password for apikey management

# TODO try to make a decorator that auto does self.verify_password on a method

class Database:
    def initialize(self, db_path) -> Result:
        self.DB_PATH = db_path
        self.conn = self.connection = sqlite3.connect(self.DB_PATH)
        self.cur = self.cursor = self.conn.cursor()
        self.query = self.cursor.execute
        self.create_user_table()
        self.create_apikey_table()
        self.create_log_table()
        return Ok

    def commit(self) -> Result:
        """Shortcut to self.connection.commit()"""
        self.connection.commit()
        return Ok

    def create_user_table(self) -> Result:
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS User (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username VARCHAR(64) UNIQUE NOT NULL,
                password_hash CHAR(60) NOT NULL
            )
        ''')
        self.commit()
        return Ok

    def insert_user(self, username, password) -> Result:
        password_hash = self.create_password_hash(password)

        self.cursor.execute('''
            INSERT INTO User (username, password_hash)
            VALUES (?, ?)
        ''', (username, password_hash))

        self.commit()
        return Ok


    def create_apikey_table(self) -> Result:
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
                created DATETIME NOT NULL,
                expiry DATETIME,
                user_id INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES User (id)
            )
        ''')
        self.commit()
        return Ok

    def create_log_table(self) -> Result:
        # TODO change user_id to apikey_id to track which apikey created the log
        # and the apikey can be reversed to a user_id easily as well.
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS Log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message TEXT NOT NULL,
                datetime DATETIME NOT NULL,
                key_id INTEGER NOT NULL,
                FOREIGN KEY (key_id) REFERENCES ApiKey (id)
            )
        ''')
        self.commit()
        return Ok

    def get_key_id(self, key) -> int | None:
        self.query('SELECT id FROM ApiKey WHERE key = ?', (key,))
        wrapped_key = self.cur.fetchone()
        if wrapped_key is None:
            return None
        return wrapped_key[0]

    def delete_logs_created_with(self, key: str | int) -> Result:
        key_id = key if type(key) is int else self.get_key_id(key)
        self.query('DELETE FROM Log WHERE key_id = ?', (key_id,))
        return Ok

    def delete_apikey(
            self, username: str, password: str, key: str | int) -> Result:
        """Deletes a key and all logs created with that key"""
        if not self.verify_password(username, password):
            return IncorrectPassword

        key_id = key if type(key) is int else self.get_key_id(key)

        self.delete_logs_created_with(key_id)

        self.cursor.execute(
                'DELETE FROM ApiKey WHERE id = ?', (key_id,))
        self.commit()
        return Ok

    def revoke_all_apikeys(self, username: str, password: str) -> Result:
        """Deletes all apikeys for a certain user 
        (deleting the logs made by those keys as well.)"""
        # TODO just use self.delete_apikey but in a for loop
        return NotImplemented


    def get_newest_apikey(self, username) -> str:
        user_id = self.get_user_id(username)

        q = 'SELECT key FROM ApiKey WHERE user_id = ? ORDER BY id DESC LIMIT 1'
        self.query(q, (user_id,))

        wrapped_key = self.cur.fetchone()
        if wrapped_key is not None:
            return wrapped_key[0]
        return None

    def create_apikey(
            self, username: str, password: str, 
            permissions: list[AccessPermission] | int) -> Result:
        """Create's a new ApiKey for the User, but doesn't return it as this is a
        side-effect function. And we keep pure-functions pure and 
        side-effect functions, side effect functions. \n
        If you need to return the newest created apikey then use 
        `self.get_newest_apikey(user)`"""

        if not self.verify_password(username, password):
            return IncorrectPassword

        # make sure you have a permissions int flag first
        if type(permissions) == list:
            permissions = flag_from_permissions_list(permissions)

        key = self.generate_apikey_str(permissions)
        self.cur.execute('SELECT id FROM User WHERE username = ?', (username,))
        user_id = self.cur.fetchone()[0]

        self.cur.execute('''
            INSERT INTO ApiKey (key, permissions, created, user_id)
            VALUES (?, ?, ?, ?)
        ''', (key, permissions, datetime.now(), user_id))
        self.commit()
        return Ok

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
        """Print out the current state of the database"""
        print("Database:", description if not None else "") 
        print("USERS:")

        users = self.select_all_from("User")
        for user in users:
            print(user)
        
        print("---")
        print("APIKEYS:")

        keys = self.select_all_from("ApiKey")
        for key in keys:
            print(key)
        
        print("---")
        print("LOGS:")

        logs = self.select_all_from("User")
        for log in logs:
            print(log)

    def create_password_hash(self, password) -> str:
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    def verify_password(self, username, password) -> bool:
        self.cursor.execute(
                'SELECT password_hash FROM User WHERE username=?', (username,))
        # SELECT password_hash returns only the hash and no other data
        stored_hash = self.cursor.fetchone()[0]
        if stored_hash:
            return bcrypt.checkpw(password.encode(), stored_hash)
        return False


    def delete_user(self, username, password) -> Result:
        """Deletes a user and all their logs"""
        if not self.verify_password(username, password):
            return IncorrectPassword
        
        user_id = self.get_user_id(username)
        apikey_ids = self.get_all_apikey_ids(username)

        # delete keys and logs
        for key_id in apikey_ids:
            self.delete_apikey(username, password, key_id)
        
        # delete user
        self.cursor.execute(
                'DELETE FROM User WHERE username = ?', (username,))
        self.commit()

        return Ok

    def get_all_apikey_ids(self, username) -> list[int]:
        user_id = self.get_user_id(username)
        self.query('SELECT id FROM ApiKey WHERE user_id = ?', (user_id,))
        wrapped_key_ids = self.cursor.fetchall()
        if wrapped_key_ids is None:
            return []
        return [id[0] for id in wrapped_key_ids]


    def get_user_id(self, username) -> int | None:
        self.cur.execute(
                "SELECT id FROM User WHERE username = ?", (username,))
        wrapped_user_id = self.cur.fetchone()
        if wrapped_user_id is not None:
            return wrapped_user_id[0]
        return None

    def can_permission(self,
            required_permission: AccessPermission, permissions: int) -> bool:
        return required_permission.value & permissions

    def insert_log(self, message, key) -> Result:
        self.cur.execute(
                'SELECT id, permissions FROM ApiKey WHERE key = ?', (key,))
        wrapped_key = self.cur.fetchone()
        if wrapped_key is None:
            return UnknownApiKey

        key_id, permissions = wrapped_key

        can_write = self.can_permission(AccessPermission.WRITE, permissions)
        if not can_write:
            return InvalidPermission

        self.cursor.execute('''
            INSERT INTO Log (message, datetime, key_id)
            VALUES (?, ?, ?)
        ''', (message, datetime.now(), key_id))

        self.commit()
        return Ok


    def test(self, users: int = 1, logs: int = 1) -> Result:
        print("Testing tmp `Database` in memory")
        test_username = 'john'
        test_password = 'password'

        # Database is empty
        assert len(self.select_all_from("User")) == 0
        assert len(self.select_all_from("Log")) == 0
        print("1: empty database... ✔")

        # add a new user ...
        self.insert_user(test_username, test_password)
        
        # Datebase has 1 user
        assert len(self.select_all_from("User")) == 1
        print("2: one user in db... ✔")

        # verify_password works as expected
        assert self.verify_password(test_username, test_password)
        assert not self.verify_password(test_username, "incorrect_password")
        print("3: password verification... ✔")

        permissions = [ AccessPermission.WRITE ]
        
        self.create_apikey(test_username, test_password, permissions)
        first_key = new_key = self.get_newest_apikey(test_username)

        self.create_apikey(test_username, test_password, 2)
        read_only_key = new_key = self.get_newest_apikey(test_username)

        # create many keys with different permissions
        for p in (4, 8, 15):
            self.create_apikey(test_username, test_password, p)
            new_key = self.get_newest_apikey(test_username)


        assert len(self.select_all_from("ApiKey")) == 5
        print("4a: create api keys... ✔")

        self.delete_apikey(test_username, test_password, new_key)

        assert len(self.select_all_from("ApiKey")) == 4
        print("4b: delete api key... ✔")


        # TODO change log insert to use an apikey with WRITE permissions

        message = "This is a test log message 124459879827305928735908"
        self.insert_log(message, first_key)

        # Cannot write a log with a read_only key
        assert self.insert_log(message, read_only_key) == InvalidPermission

        # There is 1 log in the Log table...
        assert len(self.select_all_from("Log")) == 1
        print("5: one log in db... ✔")

        self.delete_user(test_username, test_password)

        # User and their logs deletion confirmed
        assert len(self.select_all_from("ApiKey")) == 0 
        assert len(self.select_all_from("User")) == 0
        assert len(self.select_all_from("Log")) == 0
        print("6: user, keys and logs deletion... ✔")

        print("6: empty database... ✔")
        print("All `Database` tests passed... ✔")

        return Ok


if __name__ == "__main__":
    print("Testing basic impl of `Database`")
    db = Database()
    db.initialize(":memory:")
    db.test()

