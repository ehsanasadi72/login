from fastapi import FastAPI, Depends, HTTPException, status
from .auth import AuthHandler
from .models import AuthModel
from .database import MongoStorage
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer

app = FastAPI()
auth_handler = AuthHandler()
mongo = MongoStorage()
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
    if mongo.load_one('users', {'username': str(user.username)}) is not None:
        return 'Username is taken!'
    try:
        hashed_password = auth_handler.generate_hash_password(user.password)
        new_user = {'username': user.username, "password": hashed_password}
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
def login(user_details: OAuth2PasswordRequestForm = Depends()):
    """
    send parameters to check|_authentication to authenticate user
     and then generate access and refresh token
    :param user_details:
    :return:
    """
    check_authentication(user_details.username, user_details.password)

    access_token = auth_handler.encode_access(user_details.username)
    refresh_token = auth_handler.encode_refresh_token()
    return {"access token": access_token, 'refresh_token': refresh_token}


def check_current_user_tokens(token: str = Depends(security)):
    """
    check if refresh token expired or not and generate new access token
    :param token:
    :return:
    """
    return auth_handler.decode_refresh_token(token)


@app.post('/token')
def generate_new_access_token(token: str = Depends(check_current_user_tokens)):
    """
    return new access token
    :param token:
    :return:
    """
    new_access_token = auth_handler.decode_refresh_token(token)
    return {'token': new_access_token}


@app.post('/unprotected')
def unprotected():
    """
    just for test of not using authorise
    :return:
    """
    return {'whatever'}


@app.post('/protected')
def protected(detail: AuthModel = Depends(security)):
    """
    just for test of not using authorise
    :param detail:
    :return:
    """
    return {'protected': detail.username}
