import time
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

import aiohttp
import jwt
from fastapi import HTTPException, status
from fastapi.params import Depends
from fastapi.security import (
    OAuth2AuthorizationCodeBearer,
    OAuth2PasswordBearer,
)
from pydantic import BaseModel
from pydantic_core import ValidationError

from ..const import CLIENT_ID, CLIENT_SECRET, OIDC_ISSUER, OIDC_JWKS_URL

JWKS_CACHE = None
JWKS_TS = 0
JWKS_TTL = 3600  # seconds

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


class User(BaseModel):
    name: str
    email: str | None = None
    prefered_username: str | None = None
    groups: list[str] | None = None
    disabled: bool | None = None


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


if OIDC_ISSUER:
    oauth2_scheme = OAuth2AuthorizationCodeBearer(
        authorizationUrl=f"{OIDC_ISSUER}/authorization",
        tokenUrl=f"{OIDC_ISSUER}/token",
        scopes={
            "offline_access": "Offline access",
            "openid": "OpenID",
            "profile": "User profile",
            "email": "User email",
            "address": "User address",
            "phone": "User phone number",
            "groups": "User groups",
        },
        auto_error=False,
    )
else:
    oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token", auto_error=False)

oauth2_password = OAuth2PasswordBearer(tokenUrl="/token", auto_error=False)


def get_user(user_dict: dict[str, Any]):
    return User(**user_dict)


async def get_jwks():
    """Get JWKS."""

    global JWKS_CACHE, JWKS_TS

    now = time.time()
    if JWKS_CACHE and now - JWKS_TS < JWKS_TTL:
        return JWKS_CACHE

    async with aiohttp.ClientSession() as session:
        async with session.get(OIDC_JWKS_URL) as resp:
            if resp.status != 200:
                raise RuntimeError("Unable to fetch JWKS")
            JWKS_CACHE = await resp.json()
            JWKS_TS = now
            return JWKS_CACHE


async def introspect(token: str):
    """Introspect token."""
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{OIDC_ISSUER}/introspection",
            data={"token": token},
            auth=aiohttp.BasicAuth(CLIENT_ID, CLIENT_SECRET),
        ) as resp:
            if resp.status != 200:
                raise InvalidInspection(f"Invalid inspection: {resp.status}")
            return await resp.json()


async def get_userinfo(access_token: str):
    headers = {"Authorization": f"Bearer {access_token}"}
    async with aiohttp.ClientSession() as session:
        async with session.get(f"{OIDC_ISSUER}/userinfo", headers=headers) as resp:
            if resp.status != 200:
                raise InvalidToken(f"Invalid token: {resp.status}")
            return await resp.json()


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
    )

    try:
        # jwks = await get_jwks()
        payload = await introspect(token)
        if not payload["active"] or payload["client_id"] != CLIENT_ID:
            raise credentials_exception
    except Exception:
        # raise credentials_exception from e
        return None

    try:
        user = await get_userinfo(token)
        username = user.get("sub")
        if username is None:
            raise credentials_exception
        user = get_user(user)
    except (InvalidToken, InvalidInspection, RuntimeError, ValidationError):
        # raise credentials_exception from e
        return None
    return user


async def get_current_password_user(
    token: Annotated[str, Depends(oauth2_password)],
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.InvalidTokenError:
        raise credentials_exception

    return username


async def protected(
    oidc_user: Annotated[User | None, Depends(get_current_user)] = None,
    oauth2_password: Annotated[User | None, Depends(get_current_password_user)] = None,
):
    """
    Try either basic auth or OIDC token.
    Raises 401 if neither succeeds.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Basic, Bearer"},
    )
    try:
        if not (oidc_user or oauth2_password):
            raise credentials_exception
        return oidc_user or oauth2_password
    except Exception:
        raise credentials_exception


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(days=3650)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


class InvalidToken(Exception):
    """Invalid token exception."""


class InvalidInspection(Exception):
    """Invalid token exception."""
