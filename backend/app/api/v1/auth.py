from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_roles
from app.core.security import create_access_token
from app.db.session import get_db
from app.models.models import User
from app.schemas.user import TokenResponse, UserLoginRequest, UserRegisterRequest, UserResponse
from app.services.user_service import UserService

router = APIRouter(prefix="/auth", tags=["Authentication & RBAC"])


@router.post("/login", response_model=TokenResponse)
def login(payload: UserLoginRequest, db: Session = Depends(get_db)):
    """
    Authenticates user with username & password and returns a signed JWT bearer token.
    """
    user = UserService.authenticate_user(db, payload.username, payload.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "INVALID_CREDENTIALS", "message": "Invalid username or password.", "field": "password"}
        )

    token = create_access_token(data={"sub": user.username, "role": user.role, "uid": user.id})
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=UserResponse.model_validate(user)
    )


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register_user(
    payload: UserRegisterRequest,
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_roles(["ADMIN"]))
):
    """
    Registers a new user (Admin only).
    """
    existing_username = UserService.get_by_username(db, payload.username)
    if existing_username:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "ALREADY_EXISTS", "message": f"Username '{payload.username}' is already taken.", "field": "username"}
        )

    existing_email = UserService.get_by_email(db, str(payload.email))
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "ALREADY_EXISTS", "message": f"Email '{payload.email}' is already in use.", "field": "email"}
        )

    valid_roles = ["ADMIN", "ANALYST", "VIEWER"]
    role = (payload.role or "ANALYST").upper()
    if role not in valid_roles:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": "INVALID_ROLE", "message": f"Role must be one of {valid_roles}", "field": "role"}
        )

    user = UserService.create_user(
        db=db,
        username=payload.username,
        email=str(payload.email),
        password=payload.password,
        role=role
    )
    return UserResponse.model_validate(user)


@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    """
    Returns the currently authenticated user's profile and active role.
    """
    return UserResponse.model_validate(current_user)


@router.get("/users", response_model=list[UserResponse])
def list_users(
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_roles(["ADMIN"]))
):
    """
    Lists all system users (Admin only).
    """
    users = db.scalars(select(User).order_by(User.id.asc())).all()
    return [UserResponse.model_validate(u) for u in users]
