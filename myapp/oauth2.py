from datetime import datetime, timedelta
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from fastapi import Depends, status, HTTPException
from fastapi.security import OAuth2PasswordBearer

from passlib.context import CryptContext

from config import settings
from models import User
from schemas.token import TokenData
from models.database import get_db

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="tokens")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Secret key
# Algorithm
# Expiration Time

SECRET_KEY = settings.secret_key  # createdUsing openssl rand -hex 32
ALGORITHM = settings.algorithm
ACCESS_TOKEN_EXPIRE_MINUTES = settings.access_token_expire_minutes


def create_access_token(data: dict):
    to_encode = data.copy()

    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    return encoded_jwt


def verify_access_token(token: str, credentials_exception):

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        id = payload.get("current_user")
        # print(f"verify_access_token -- id: {id} {type(id)}")
        if id is None:
            raise credentials_exception
        token_data = TokenData(id=id)
        # print(f"verify_access_token -- token_data: {token_data}")

    except JWTError:
        raise credentials_exception

    return token_data


def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=f"Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    token = verify_access_token(token, credentials_exception)
    user = db.query(User).filter(User.id == token.id).first()
    # print(f"get_current_user -- user: {user.to_dict()}")
    return user

def hash(password: str):
    return pwd_context.hash(password)

def verify(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)