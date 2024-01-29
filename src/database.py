import bcrypt 
import secrets
import sqlite3

from common import *

# TODO look for a way to use pydantic more directly with the db
#       like returning pydantic models directly from db calls...

# TODO update the Database to reflect the api_key model
# TODO using apiKeys to create logs instead of passwords
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
        self.cur.execute(
                'SELECT id, username FROM User WHERE username=?', (username,))
        user = self.cur.fetchone()
        return User(user_id = user[0], username = user[1])


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

    def delete_apikey(self, username: str, password: str, key: str) -> Result:
        if not self.verify_password(username, password):
            return IncorrectPassword

        self.cursor.execute(
                'DELETE FROM ApiKey WHERE key = ?', (key,))
        self.commit()
        return Ok

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

    def get_newest_apikey(user) -> str:
        q = 'SELECT key FROM ApiKey WHERE user_id = ? ORDER BY id DESC LIMIT 1'
        self.query(q, (user_id))

        wrapped_key = self.cur.fetchone()
        if wrapped_key is not None:
            return wrapped_key[0]
        return None


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

    def can_permission(
            required_permission: AccessPermission, permissions: int) -> bool:
        return required_permission.value & permissions

    def insert_log(self, message, key) -> Result:
        # TODO use apikey with write permissions instead of username and pass

        self.cur.execute(
                'SELECT id, permissions FROM ApiKey WHERE key = ?', (key,))
        possible_key = self.cur.fetchone()
        if possible is None:
            return UnknownApiKey

        key_id, permissions = possible_key

        # TODO check for WRITE permission 
        # eg: self.can_permissions(AccessPermission, permissions: int | list)
        if not self.can_permission(AccessPermission.WRITE, permissions):
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

        # create many keys with different permissions
        for p in (3, 4, 8, 9):
            new_key = self.create_apikey(test_username, test_password, p)
            print(new_key)

        assert len(self.select_all_from("ApiKey")) == 5
        print("4a: create api keys... ✔")

        key = new_key[1]
        self.delete_apikey(test_username, test_password, key)

        assert len(self.select_all_from("ApiKey")) == 4
        print("4b: delete api key... ✔")


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
        print("6: user, keys and logs deletion... ✔")

        print("6: empty database... ✔")
        print("All `Database` tests passed... ✔")

        return Ok


if __name__ == "__main__":
    print("Testing basic impl of `Database`")
    db = Database()
    db.initialize(":memory:")
    db.test()

