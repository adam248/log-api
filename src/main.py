from fastapi import FastAPI
from fastapi.responses import RedirectResponse

from common import *
from database import Database

# APP & DATABASE DECLARATION ------------------------------------------------


__version__ = "0.1.1"
description = """
Log API allows for simple user-based logging with API keys.
"""
DB_PATH = "log.db"

app = FastAPI(
        title = 'Log API',
        description = description,
        summary = 'A simple Logging API',
        version = __version__,
        contact = {
            "name": "Adam Butler",
            "email": "adamjbutler091@gmail.com",
            }
        )

db = Database()
db.initialize(DB_PATH)


# NON-API URLS --------------------------------------------------------------

@app.get("/", include_in_schema=False)
async def root():
    """Redirects to /docs page"""
    return RedirectResponse(url='/docs')

# USER ENDPOINTS ------------------------------------------------------------

# TODO replace fake_user_db with database call
fake_user_db = [
        User(user_id=0, username="alex"),
        User(user_id=1, username="jones"),
        User(user_id=2, username="dave"),
        ]


@app.get("/users")
async def read_users(user_id: int = None, username: str = None) -> list[User]:
    """ 
    Defaults to returning all users.\n
    If all query params are received, then `user_id` will be used.
    """
    if user_id is not None:
        return [ fake_user_db[user_id] ]
    elif username is not None:
        for user in fake_user_db:
            if user.username == username:
                return [ user ]
    return fake_user_db 


@app.post("/users")
async def create_user(user: UserNew) -> User:
    # TODO user_id is set by the database at creation time
    user = User(username=user.username, user_id=len(fake_user_db))
    if user:
        return Success
    else:
        # TODO find out how to return a HTTP Error code
        # for example the username may already exist
        return Fail


# LOG ENDPOINTS -------------------------------------------------------------

# TODO replace fake_log_db with database call
fake_log_db = [
            Log(message="log 0, the first of its name...", user_id=6, log_time=datetime.now()),
            Log(message="are we there yet?", user_id=3, log_time=datetime.now()),
            Log(message="ERROR: on line 38", user_id=2, log_time=datetime.now()),
        ]


@app.get("/logs")
async def read_logs() -> list[Log]:
    """ 
    See all logs...
    """
    return fake_log_db


@app.post("/logs")
async def create_log(log: LogNew) -> Log:
    # TODO log_id needs to be set by the db at creation time
    log = Log(user_id=log.user_id, message=log.message, log_time=datetime.now())
    fake_log_db.append(log)
    return log


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=1234)

