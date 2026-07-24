from pydantic import BaseModel
from typing import Optional


class UserLogin(BaseModel):
    username: str
    password: str


class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None
