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
    if mongo.load('users', {'username': str(user.username)}) is not None:
        return 'Username is taken!'
    try:
        hashed_password = auth_handler.generate_hash_password(user.password)
        new_user = {'username': user.username, "password": hashed_password}
        mongo.store_one(new_user, 'users')
        return 'you signed up successfully'
    except:
        return "failed to sign up please try again"


@app.post('/login')
def login(user_details: OAuth2PasswordRequestForm = Depends()):
    user = mongo.load('users', {'username': user_details.username})
    if user is None:
        return HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail='invalid username'
        )
    elif not auth_handler.verify_password(user_details.password, user['username']):
        return HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail='invalid password'
        )

    access_token = auth_handler.encode_access(user_details.username)
    refresh_token = auth_handler.encode_refresh_token()
    return {"access token": access_token, 'refresh_token': refresh_token}


@app.get('/refresh_token')
def generate_new_access_token(refresh_token: str = Depends(security)):
    access_token = auth_handler.decode_refresh_token(refresh_token)
    return {'access_token': access_token}


@app.post('/unprotected')
def unprotected():
    return {'whatever'}


@app.post('/protected')
def protected(detail: AuthModel = Depends(security)):
    return {'protected': detail.username}
