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
from services import db_service
from models.database import SessionLocal
from services.db_service import UserCRUD
from schemas import user_schema

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

    email = verify_token(token)
    print(f"get_current_user email: {email}")
    if email is None:
        raise credentials_exception

    user = db_service.UserCRUD(db).get_user_by_email(email)
    if user is None:
        raise credentials_exception
    # print(f"get_current_user user: {user.to_dict()}")
    # user_out = user_schema.UserOut.model_validate(user)
    # print(f"get_current_user UserOut: {user_out}")

    # 세션 활동 업데이트
    session_id = request.cookies.get("session_id")
    if session_id:
        db_service.UserSessionCRUD(db).update_session_activity(session_id)

    return user

def create_admin_user() -> user_model.User:
    """Create an admin user if it doesn't exist"""
    admin = user_model.User(
        username=settings.admin_user,
        email=settings.admin_email,
        password=settings.admin_password,
        is_admin=True,
    )
    db = SessionLocal()
    user_crud = UserCRUD(db)

    # if admin user already exists , return
    check_user = user_crud.get_user_by_email(admin.email)
    if check_user:
        return check_user
    # add admin user to db
    user_crud.create_user(admin)

    return admin
