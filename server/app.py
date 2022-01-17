from typing import List, Dict

from fastapi import FastAPI, Depends, HTTPException, status, Response
from .auth import AuthHandler
from .models import AuthModel
from .database import MongoStorage, MongoConnection
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer

app = FastAPI()
auth_handler = AuthHandler()
security = OAuth2PasswordBearer(tokenUrl='token')


@app.post('/sign_up')
def sign_up(user: AuthModel):
    """
    if the username isn't taken it will sign up the user
    and save it to database and any problem happened let
     the user know
    :param user: username and password
    :return:
    """
    with MongoConnection():
        mongo = MongoStorage()
        if mongo.load_one('users', {'username': str(user.username)}) is not None:
            return 'Username is taken!'
    try:
        hashed_password = auth_handler.generate_hash_password(user.password)
        new_user = {'username': user.username, "password": hashed_password}
        with MongoConnection():
            mongo = MongoStorage()
            mongo.store_one(new_user, 'users')
        return 'you signed up successfully'
    except:
        return "failed to sign up please try again"


def check_authentication(username: str, password: str):
    """
    authenticate the user and if there was any problem raise error
    :param username:
    :param password:
    :return:
    """
    with MongoConnection():
        mongo = MongoStorage()
        user = mongo.load_one('users', {'username': username})
        if user is None:
            return HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail='invalid username'
            )
        elif not auth_handler.verify_password(password, user['password']):
            return HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail='invalid password'
            )


@app.post('/login')
def login(response: Response, user_details: OAuth2PasswordRequestForm = Depends()):
    """
    send parameters to check|_authentication to authenticate user
     and then generate access and refresh token
    :param response:
    :param user_details:
    :return:
    """
    check_authentication(user_details.username, user_details.password)

    access_token = auth_handler.encode_access_token(user_details.username)
    refresh_token = auth_handler.encode_refresh_token(user_details.username)
    response.headers['refresh_key'] = refresh_token
    response.headers['access_key'] = access_token


def check_current_user_access_token(token: str = Depends(security)):
    """
    check if refresh token expired or not and generate new access token
    :param token:
    :return:
    """
    return auth_handler.decode_access_token(token)


@app.post('/protected')
def protected(detail: AuthModel, token: str = Depends(check_current_user_access_token)):
    """
    just for test of not using authorise
    :param token:
    :param detail:
    :return:
    """
    return {'protected': detail}


@app.post('/unprotected')
def unprotected():
    """
    just for test of not using authorise
    :return:
    """
    return {'whatever'}
