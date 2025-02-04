
from models.database import SessionLocal
from models import user_model

from config import settings
from services import user_crud, oauth2_service as oauth2


def create_admin_user() -> user_model.User:
    """Create an admin user if it doesn't exist"""
    admin = user_model.User(
        username=settings.admin_user,
        email=settings.admin_email,
        password=oauth2.hash(settings.admin_password),
        is_admin=True,
    )
    db = SessionLocal()
    crud = user_crud.UserCRUD(db)

    # if admin user already exists , return
    check_user = crud.get_user_by_email(admin.email)
    if check_user:
        return check_user
    # add admin user to db
    crud.create_user(admin)

    return admin

# def verify_password(plain: str, hash: str) -> bool:
#     """Hash <plain> and compare with <hash> from the database"""
#     return pwd_context.verify(plain, hash)


# def get_hash(plain: str) -> str:
#     """Return the hash of a <plain> string"""
#     return pwd_context.hash(plain)


# def get_jwt_username(token: str) -> str | None:
#     """Return username from JWT access <token>"""
#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#         if not (username := payload.get("sub")):
#             return None
#     except jwt.JWTError:
#         return None
#     return username


# def get_current_user(token: str) -> User | None:
#     """Decode an OAuth access <token> and return the User"""
#     if not (username := get_jwt_username(token)):
#         return None
#     if user := lookup_user(username):
#         return user
#     return None


# def lookup_user(name: str) -> User | None:
#     """Return a matching User fron the database for <name>"""
#     if user := data.get(name):
#         return user
#     return None


# def auth_user(name: str, plain: str) -> User | None:
#     """Authenticate user <name> and <plain> password"""
#     if not (user := lookup_user(name)):
#         return None
#     if not verify_password(plain, user.hash):
#         return None
#     return user


# def create_access_token(data: dict, expires: datetime.timedelta | None = None):
#     """Return a JWT access token"""
#     src = data.copy()
#     now = datetime.utcnow()
#     expires = expires or datetime.timedelta(minutes=TOKEN_EXPIRES)
#     src.update({"exp": now + expires})
#     encoded_jwt = jwt.encode(src, SECRET_KEY, algorithm=ALGORITHM)
#     return encoded_jwt


# # --- CRUD passthrough stuff


# def get_all() -> list[User]:
#     return data.get_all()


# def get_one(name) -> User:
#     return data.get_one(name)


# def create(user: User) -> User:
#     return data.create(user)


# def modify(name: str, user: User) -> User:
#     return data.modify(name, user)


# def delete(name: str) -> None:
#     return data.delete(name)
