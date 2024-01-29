from datetime import datetime
from enum import Enum

from pydantic import BaseModel

# Enums

class AccessPermission(Enum):
    """This Enum is used with the ApiKey permissions `int`
    that is a bitwise-flag that directly translates to a list[AccessPermission].
    """
    WRITE = 1
    READ = 2
    DELETE = 4
    ADMIN = 8

# Pydantic Models

class ApiKey(BaseModel):
    key: str
    permissions: int

    def permissions_list(self) -> list[AccessPermission]:
        """Convenience function to get the list of AccessPermission enums 
        from the `self.permissions` bitwise flag."""
        return [p for p in AccessPermission 
                if self.permissions & p.value]

class UserNew(BaseModel):
    username: str
    password: str

class User(BaseModel):
    user_id: int
    username: str

class LogNew(BaseModel):
    message: str
    apikey: str

class Log(BaseModel):
    log_time: datetime
    message: str

# Pydantic Result types for response bodies

class Success(BaseModel):
    message: str = "Operation successful"

class Fail(BaseModel):
    message: str = "Operation failed"

# Result types

class Result(Exception):
    pass

class Ok(Result):
    pass

class DeletionFailed(Result):
    pass

class IncorrectPassword(Result):
    pass

class InsertionFailed(Result):
    pass

# Utilites - functions

def flag_to_permissions_list(flag: int) -> list[AccessPermission]:
    """Converts a flag to list[AccessPermission]"""
    return [p for p in AccessPermission
            if flag & p.value]

def flag_from_permissions_list(
        permissions_list: list[AccessPermission]) -> int:
    """Creates a bitwise-flag that matches the permission_list""" 
    return sum(p.value for p in permissions_list)

if __name__ == "__main__":
    import secrets
    key = secrets.token_urlsafe(16)
    permissions = 3
    api_key = ApiKey(key=key, permissions=permissions)
    assert [AccessPermission.WRITE, AccessPermission.READ] \
            == api_key.permissions_list()
    print("API Key tests passed...")

