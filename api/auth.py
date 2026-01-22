# api/auth.py
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from passlib.context import CryptContext

# ---- CHANGE THESE (or move to env vars) ----
JWT_SECRET = "CHANGE_ME_SUPER_SECRET"
JWT_ALG = "HS256"
ACCESS_TOKEN_MINUTES = 60

# Demo single user (multinational dashboard style would use DB later)
DEMO_USERNAME = "admin"
# Password is: admin123
DEMO_PASSWORD_HASH = "$2b$12$kq2a3q1y2WnZ6xj7fKJQ7eXq9y5rYQwq0a8yQ3zZ4m1yq2b6jOq8e"

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2 = OAuth2PasswordBearer(tokenUrl="/auth/login")


def verify_password(plain: str, hashed: str) -> bool:
    return pwd.verify(plain, hashed)


def create_access_token(sub: str, minutes: int = ACCESS_TOKEN_MINUTES) -> str:
    exp = datetime.utcnow() + timedelta(minutes=minutes)
    payload = {"sub": sub, "exp": exp}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def authenticate_user(username: str, password: str) -> bool:
    if username != DEMO_USERNAME:
        return False
    return verify_password(password, DEMO_PASSWORD_HASH)


def get_current_user(token: str = Depends(oauth2)) -> str:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        sub = payload.get("sub")
        if not sub:
            raise JWTError("missing sub")
        return sub
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
