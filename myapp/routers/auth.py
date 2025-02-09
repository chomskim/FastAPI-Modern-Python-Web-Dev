# routes/auth.py
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from models.database import get_db
from models import user_model as model
from services import db_service as crud
from services.oauth2_service import REFRESH_TOKEN_EXPIRE_DAYS, pwd_context
from services.oauth2_service import create_access_token, create_refresh_token, get_current_user
from schemas import token_schema

router = APIRouter(tags=["Authentication"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
# pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


@router.post("/login", response_model=token_schema.Token)
async def login(
    response: Response,
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    user_crud = crud.UserCRUD(db)
    user = user_crud.get_user_by_email(form_data.username)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="username or email not found",
        )
    if not pwd_context.verify(form_data.password, user.password):
        # user_crud.increment_failed_login(user)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    # 로그인 성공 처리
    access_token = create_access_token(data={"sub": user.email})
    refresh_token = create_refresh_token(data={"sub": str(user.id)})

    # Refresh 토큰 저장
    crud.RefreshTokenCRUD(db).create_refresh_token(
        user_id=user.id,
        token=refresh_token,
        expires_at=datetime.now(timezone.utc)
        + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        device_info=request.headers.get("user-agent"),
        ip_address=request.client.host,
    )

    # 세션 생성
    session = crud.UserSessionCRUD(db).create_session(
        user_id=user.id,
        ip_address=request.client.host,
        user_agent=request.headers.get("user-agent"),
    )

    # 마지막 로그인 시간 업데이트
    user_crud.update_last_login(user)

    # 쿠키 설정
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
    )

    response.set_cookie(
        key="session_id",
        value=session.session_id,
        httponly=True,
        secure=True,
        samesite="lax",
    )

    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/token/refresh")
def refresh_token(
    request: Request, db: Session = Depends(get_db)
):
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token missing"
        )

    token_crud = crud.RefreshTokenCRUD(db)
    db_token = token_crud.get_refresh_token(refresh_token)

    if not db_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    user = crud.UserCRUD(db).get_user(db_token.user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found"
        )

    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/logout")
def logout(
    response: Response,
    request: Request,
    db: Session = Depends(get_db),
):
    session_id = request.cookies.get("session_id")
    if session_id:
        # 현재 세션 종료
        crud.UserSessionCRUD(db).end_session(session_id)

    # Refresh 토큰 폐기
    refresh_token = request.cookies.get("refresh_token")
    if refresh_token:
        token_crud = crud.RefreshTokenCRUD(db)
        db_token = token_crud.get_refresh_token(refresh_token)
        if db_token:
            db_token.is_revoked = True
            db.commit()

    # 쿠키 삭제
    response.delete_cookie(key="refresh_token", path="/",
                           secure=True, httponly=True)
    response.delete_cookie(key="session_id", path="/",
                           secure=True, httponly=True)

    return {"message": "Successfully logged out"}


@router.post("/logout/all-devices")
async def logout_all_devices(
    response: Response,
    db: Session = Depends(get_db),
    current_user: model.User = Depends(get_current_user),
):
    # 모든 Refresh 토큰 폐기
    crud.RefreshTokenCRUD(db).revoke_all_user_tokens(current_user.id)

    # 모든 활성 세션 종료
    sessions = crud.UserSessionCRUD(db).get_active_sessions(current_user.id)
    for session in sessions:
        crud.UserSessionCRUD(db).end_session(session.session_id)

    # 현재 세션의 쿠키도 삭제
    response.delete_cookie(key="refresh_token", path="/",
                           secure=True, httponly=True)
    response.delete_cookie(key="session_id", path="/",
                           secure=True, httponly=True)

    return {"message": "Logged out from all devices"}


@router.get("/sessions/active")
async def get_active_sessions(
    db: Session = Depends(get_db),
    current_user: model.User = Depends(get_current_user),
):
    sessions = crud.UserSessionCRUD(db).get_active_sessions(current_user.id)
    return [
        {
            "session_id": session.session_id,
            "ip_address": session.ip_address,
            "user_agent": session.user_agent,
            "last_activity": session.last_activity,
            "created_at": session.created_at,
        }
        for session in sessions
    ]


@router.put("/users/me/password")
async def change_password(
    old_password: str,
    new_password: str,
    db: Session = Depends(get_db),
    current_user: model.User = Depends(get_current_user),
):
    if not pwd_context.verify(old_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect password"
        )

    # 새 비밀번호 유효성 검사
    if len(new_password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters long",
        )

    # 비밀번호 업데이트
    current_user.hashed_password = pwd_context.hash(new_password)
    db.commit()

    # 다른 세션 모두 종료 및 토큰 폐기
    crud.RefreshTokenCRUD(db).revoke_all_user_tokens(current_user.id)

    return {"message": "Password changed successfully"}


@router.get("/users/me")
async def read_current_user(current_user: model.User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "id_hospital": current_user.id_hospital,
        "username": current_user.username,
        "name": current_user.name,
        "contact": current_user.contact,
        "email": current_user.email,
        "is_active": current_user.is_active,
        "last_login": current_user.last_login,
        "created_at": current_user.created_at,
    }


@router.post("/users/me/password")
async def check_password(
    password: str,
    current_user: model.User = Depends(get_current_user),
):
    if not pwd_context.verify(password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    return {"message": "password ok"}


@router.put("/users/me/name")
async def change_name(
    name: str,
    db: Session = Depends(get_db),
    current_user: model.User = Depends(get_current_user),
):
    current_user.name = name
    db.commit()
    return {"message": "Name updated successfully"}


@router.put("/users/me/contact")
async def change_contact(
    contact: str,
    db: Session = Depends(get_db),
    current_user: model.User = Depends(get_current_user),
):
    current_user.contact = contact
    db.commit()
    return {"message": "Contact updated successfully"}
