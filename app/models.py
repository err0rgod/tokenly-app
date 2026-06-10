from sqlmodel import SQLModel, Field
from typing import Optional
from datetime import datetime

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
    email: str = Field(index=True, unique=True)
    hashed_password: str
    is_active: bool = Field(default=True)

class RefreshSession(SQLModel, table=True):
    session_id: str = Field(primary_key=True)
    user_id: str
    token_hash: str
    expires_at: datetime
    revoked: bool = Field(default=False)

class JwtBlacklist(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_name: str
    jti: str
    expired_at: datetime
