from fastapi import Response, status, HTTPException, Depends, APIRouter
from sqlalchemy.orm import Session

from models.database import get_db
from models import user_model
from schemas import user_schema
from services import oauth2_service as oauth2
from services.db_service import UserCRUD

router = APIRouter(prefix="/users", tags=["Users"])

@router.post("/", status_code=status.HTTP_201_CREATED, response_model=user_schema.UserOut)
def create_user(
    user: user_schema.UserCreate,
    db: Session = Depends(get_db),
    current_user: user_model.User = Depends(oauth2.get_current_user),
):
    print(f"current_user(user_model.User): {current_user.to_dict()}")
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"User not authenticated",
        )
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"User not authorized to create user",
        )
    
    user_crud = UserCRUD(db)

    # if user already exists raise error
    check_user = user_crud.get_user_by_email(user.email)

    if check_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"User with email: '{user.email}' already exists.",
        )

    # hash user given password and add user in db
    user_crud.create_user(user)
    new_user = user_crud.get_user_by_email(user.email)
    print(f"new_user: {new_user.to_dict()}")
    return new_user


# fetch user information by id
@router.get("/{id}", response_model=user_schema.UserOut)
def get_user(
    id: int,
    db: Session = Depends(get_db),
    current_user: user_model.User = Depends(oauth2.get_current_user),
):
    user_crud = UserCRUD(db)
    user = user_crud.get_user(id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with id: {id} does not exist",
        )

    return user


# fetch all users
@router.get("/", response_model=list[user_schema.UserOut])
def get_users(
    db: Session = Depends(get_db),
    current_user: user_schema.UserOut = Depends(oauth2.get_current_user),
):
    user_crud = UserCRUD(db)
    users = user_crud.get_users()

    return users
