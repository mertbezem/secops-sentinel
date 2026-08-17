from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging import logger
from app.core.security import hash_password, verify_password
from app.models.models import User


class UserService:
    @staticmethod
    def get_by_username(db: Session, username: str) -> User | None:
        return db.scalar(select(User).where(User.username == username))

    @staticmethod
    def get_by_email(db: Session, email: str) -> User | None:
        return db.scalar(select(User).where(User.email == email))

    @staticmethod
    def get_by_id(db: Session, user_id: int) -> User | None:
        return db.get(User, user_id)

    @classmethod
    def authenticate_user(cls, db: Session, username: str, password: str) -> User | None:
        user = cls.get_by_username(db, username)
        if not user or not user.is_active:
            return None
        if not verify_password(password, user.hashed_password):
            return None
        return user

    @classmethod
    def create_user(
        cls,
        db: Session,
        username: str,
        email: str,
        password: str,
        role: str = "ANALYST"
    ) -> User:
        hashed_pwd = hash_password(password)
        user = User(
            username=username,
            email=email,
            hashed_password=hashed_pwd,
            role=role.upper(),
            is_active=True
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        logger.info(f"[UserService] Created user '{username}' with role '{role}'.")
        return user

    @classmethod
    def seed_default_users(cls, db: Session) -> None:
        """
        Seeds default admin and analyst users if they don't exist.
        """
        admin_user = cls.get_by_username(db, "admin")
        if not admin_user:
            cls.create_user(
                db=db,
                username="admin",
                email="admin@secops.local",
                password="admin123",
                role="ADMIN"
            )

        analyst_user = cls.get_by_username(db, "analyst")
        if not analyst_user:
            cls.create_user(
                db=db,
                username="analyst",
                email="analyst@secops.local",
                password="analyst123",
                role="ANALYST"
            )
