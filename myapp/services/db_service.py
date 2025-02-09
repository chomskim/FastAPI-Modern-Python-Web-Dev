# services/crud.py
from datetime import datetime, timedelta, timezone
from typing import Optional

from passlib.context import CryptContext
from sqlalchemy.orm import Session
from models import user_model
from schemas import user_schema

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class UserCRUD:
    def __init__(self, db: Session):
        self.db = db

    def get_user(self, user_id: int) -> Optional[user_model.User]:
        return (
            self.db.query(user_model.User)
            .filter(user_model.User.id == user_id)
            .first()
        )

    def get_users_by_username(self, username: str) -> list[user_model.User]:
        return (
            self.db.query(user_model.User)
            .filter(user_model.User.username == username)
            .all()
        )

    def get_user_by_email(self, email: str) -> Optional[user_model.User]:
        return (
            self.db.query(user_model.User)
            .filter(user_model.User.email == email)
            .first()
        )

    def get_users(self, skip: int = 0, limit: int = 100) -> list[user_model.User]:
        return self.db.query(user_model.User).offset(skip).limit(limit).all()

    def create_user(self, user: user_schema.UserCreate) -> user_model.User:
        db_user = user_model.User(
            username=user.username, 
            email=user.email, 
            password=pwd_context.hash(user.password),
            is_admin=user.is_admin 
        )
        print(f"db_user: {db_user.to_dict()}")
        self.db.add(db_user)
        self.db.commit()
        self.db.refresh(db_user)
        return db_user

    def update_last_login(self, user: user_model.User):
        user.last_login = datetime.now(timezone.utc)
        self.db.commit()


class RefreshTokenCRUD:
    def __init__(self, db: Session):
        self.db = db

    def create_refresh_token(
        self,
        user_id: int,
        token: str,
        expires_at: datetime,
        device_info: str = None,
        ip_address: str = None,
    ) -> user_model.RefreshToken:
        db_token = user_model.RefreshToken(
            user_id=user_id,
            token=token,
            expires_at=expires_at,
            device_info=device_info,
            ip_address=ip_address,
        )
        self.db.add(db_token)
        self.db.commit()
        self.db.refresh(db_token)
        return db_token

    def get_refresh_token(self, token: str) -> Optional[user_model.RefreshToken]:
        return (
            self.db.query(user_model.RefreshToken)
            .filter(
                user_model.RefreshToken.token == token,
                user_model.RefreshToken.is_revoked is False,
                user_model.RefreshToken.expires_at > datetime.now(timezone.utc),
            )
            .first()
        )

    def revoke_all_user_tokens(self, user_id: int):
        self.db.query(user_model.RefreshToken).filter(user_model.RefreshToken.user_id == user_id).update({"is_revoked": True})
        self.db.commit()


class UserSessionCRUD:
    def __init__(self, db: Session):
        self.db = db

    def create_session(
        self, user_id: int, ip_address: str, user_agent: str
    ) -> user_model.UserSession:
        session = user_model.UserSession(
            user_id=user_id, ip_address=ip_address, user_agent=user_agent
        )
        self.db.add(session)
        self.db.commit()
        self.db.refresh(session)
        return session

    def update_session_activity(self, session_id: str):
        session = (
            self.db.query(user_model.UserSession)
            .filter(user_model.UserSession.session_id == session_id)
            .first()
        )
        if session:
            session.last_activity = datetime.now(timezone.utc)
            self.db.commit()

    def end_session(self, session_id: str):
        self.db.query(user_model.UserSession).filter(
            user_model.UserSession.session_id == session_id
        ).update({"is_active": False})
        self.db.commit()

    def get_active_sessions(self, user_id: int) -> list[user_model.UserSession]:
        return (
            self.db.query(user_model.UserSession)
            .filter(
                user_model.UserSession.user_id == user_id,
                user_model.UserSession.is_active is True,
            )
            .all()
        )

