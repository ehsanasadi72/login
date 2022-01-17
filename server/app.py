from typing import Union

from fastapi import FastAPI, Depends, HTTPException, status, Response, Header
from jwt import ExpiredSignatureError, InvalidTokenError
from .auth import AuthHandler
from .models import AuthModel
from .database import MongoStorage, MongoConnection
from fastapi.security import OAuth2PasswordRequestForm
import re

app = FastAPI()
auth_handler = AuthHandler()


def check_password_strength(password: str):
    if not re.findall('=.*[A-Z]', password):
        return 'your password must contain at least one uppercase'
    elif not re.findall('=.*[a-z]', password):
        return 'your password must contain at least one lowercase'
    elif not re.findall('=.*?[0-9]', password):
        return 'your password must contain at least one number'
    elif not re.findall('.{8,}', password):
        return 'your password must contain 8 characters'
    else:
        return False


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
        if check_password_strength(user.password):
            return 'password not strong enough try again'
        else:
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


def check_current_user_tokens(access: str = Header('access'), refresh: str = Header('refresh')):
    """
    check if refresh token expired or not and if it was expired
    check refresh and if acceptable generate new access
    :param access:
    :param refresh:
    :return:
    """
    try:
        auth_handler.decode_access_token(access)
        print('acceptable access')
    except:
        auth_handler.decode_refresh_token(refresh)
        print('acceptable refresh')


@app.post('/protected')
def protected(detail: AuthModel, token=Depends(check_current_user_tokens)):
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
