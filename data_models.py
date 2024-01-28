from datetime import datetime

from pydantic import BaseModel

# TODO update the database.py to reflect the api_key model

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

