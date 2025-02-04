import os
from fastapi import FastAPI, Response, status, HTTPException, Depends, APIRouter
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from models.database import get_db
import models
import schemas
import oauth2
from config import settings

router = APIRouter(prefix="/users", tags=["Users"])

router = APIRouter(prefix="/users", tags=["Users"])

@router.post("/", status_code=status.HTTP_201_CREATED, response_model=schemas.UserOut)
def create_user(
    user: schemas.UserCreate,
    db: Session = Depends(get_db),
    current_user: schemas.UserOut = Depends(oauth2.get_current_user),
):
    # print(f"current_user: {current_user.to_dict()}")
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"User not authenticated",
        )
    if current_user.name != settings.admin_name:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"User not authorized to create user",
        )
    new_user = models.User(**user.dict())
    # if user already exists raise error
    check_user = db.query(models.User).filter(models.User.email == new_user.email).first()

    if check_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"User with email: '{new_user.email}' already exists.",
        )

    # hash user given password and add user in db
    new_user.password = oauth2.hash(user.password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


# fetch user information by id
@router.get("/{id}", response_model=schemas.UserOut)
def get_user(
    id: int,
    db: Session = Depends(get_db),
    current_user: schemas.UserOut = Depends(oauth2.get_current_user),
):
    user = db.query(models.User).filter(models.User.id == id).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with id: {id} does not exist",
        )

    return user


# fetch all users
@router.get("/", response_model=list[schemas.UserOut])
def get_users(
    db: Session = Depends(get_db),
    current_user: schemas.UserOut = Depends(oauth2.get_current_user),
):
    users = db.query(models.User).all()
    return users

@router.post("/login", response_model=schemas.Token)
def login(
    user_credentials: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):

    user = (
        db.query(models.User)
        .filter(models.User.email == user_credentials.username)
        .first()
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail=f"Invalid Credentials"
        )

    if not oauth2.verify(user_credentials.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail=f"Invalid Credentials"
        )

    # create a token
    # return token

    access_token = oauth2.create_access_token(data={"current_user": user.id})

    return {"access_token": access_token, "token_type": "bearer"}

@router.get("/me", response_model=schemas.UserOut)
def me(current_user: schemas.UserOut = Depends(oauth2.get_current_user)):
    return current_user