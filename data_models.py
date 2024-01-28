from datetime import datetime
from enum import Enum

from pydantic import BaseModel

class AccessPermission(Enum):
    """This Enum is used with the ApiKey permissions `int`
    that is a bitwise-flag that directly translates to a list[AccessPermission].
    """
    WRITE = 1
    READ = 2
    DELETE = 4
    ADMIN = 8

class ApiKey(BaseModel):
    key: str
    permissions: int

    @staticmethod
    def from_permissions_list(permissions_list) -> int:
        """Creates a bitwise-flag that matches the permission_list""" 
        return sum(p.value for p in permissions_list)

    def to_permissions_list(self) -> list[AccessPermission]:
        """Returns a list of AccessPermissions that match 
        the self.permissions bitwise-flag."""
        return [p for p in AccessPermission 
                if self.permissions & p.value]

class UserNew(BaseModel):
    username: str
    password: str

class User(BaseModel):
    username: str
    api_keys: list[str]

class LogNew(BaseModel):
    api_key: str
    message: str

class Log(BaseModel):
    message: str
    log_time: datetime

if __name__ == "__main__":
    import secrets
    key = secrets.token_urlsafe(16)
    permissions = 3
    api_key = ApiKey(key=key, permissions=permissions)
    assert [AccessPermission.WRITE, AccessPermission.READ] \
            == api_key.to_permissions_list()
    print("API Key tests passed...")
