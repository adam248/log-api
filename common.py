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

    def permissions_list(self) -> list[AccessPermission]:
        """Conveniance function to get the list of AccessPermission enums 
        from the `self.permissions` bitwise flag."""
        return [p for p in AccessPermission 
                if self.permissions & p.value]

    @staticmethod
    def flag_to_permissions_list(flag: int) -> list[AccessPermission]:
        """Converts a flag to list[AccessPermission]"""
        return [p for p in AccessPermission
                if flag & p.value]

    @staticmethod
    def flag_from_permissions_list(
            permissions_list: list[AccessPermission]) -> int:
        """Creates a bitwise-flag that matches the permission_list""" 
        return sum(p.value for p in permissions_list)


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

class Ok(Exception):
    pass

class IncorrectPassword(Exception):
    pass

class DeletionFailed(Exception):
    pass

if __name__ == "__main__":
    import secrets
    key = secrets.token_urlsafe(16)
    permissions = 3
    api_key = ApiKey(key=key, permissions=permissions)
    assert [AccessPermission.WRITE, AccessPermission.READ] \
            == api_key.permissions_list()
    print("API Key tests passed...")

