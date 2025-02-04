# auth.py
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from passlib.context import CryptContext

from error import credentials_exception
from config import settings
from models import user_model, database
from services import user_crud


SECRET_KEY = settings.secret_key
ALGORITHM = settings.algorithm
ACCESS_TOKEN_EXPIRE_MINUTES = settings.access_token_expire_minutes
REFRESH_TOKEN_EXPIRE_DAYS = settings.refresh_token_expire_days


oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="tokens",  
    scheme_name="JWT",  
)
# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="tokens")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        sub = payload.get("sub")
        if sub is None:
            raise credentials_exception
    
    except JWTError:
        raise credentials_exception

    return sub

def get_current_user(
    request: Request,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(database.get_db),
) -> user_model.User:

    username = verify_token(token)
    if username is None:
        raise credentials_exception

    user = user_crud.UserCRUD(db).get_user_by_username(username)
    if user is None:
        raise credentials_exception

    # 세션 활동 업데이트
    session_id = request.cookies.get("session_id")
    if session_id:
        user_crud.UserSessionCRUD(db).update_session_activity(session_id)

    return user

# def get_current_user(
#     token: str = Depends(oauth2_scheme), db: Session = Depends(database.get_db)
# ):
#     credentials_exception = HTTPException(
#         status_code=status.HTTP_401_UNAUTHORIZED,
#         detail=f"Could not validate credentials",
#         headers={"WWW-Authenticate": "Bearer"},
#     )
#     token = verify_access_token(token, credentials_exception)
#     user = db.query(models.User).filter(models.User.id == token.id).first()
#     # print(f"get_current_user -- user: {user.to_dict()}")
#     return user

def hash(password: str):
    return pwd_context.hash(password)


def verify(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)
