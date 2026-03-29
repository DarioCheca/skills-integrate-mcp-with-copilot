"""
Data models for authentication and activities
"""

from pydantic import BaseModel, EmailStr
from typing import Optional


class UserBase(BaseModel):
    email: EmailStr
    full_name: str


class UserRegister(UserBase):
    password: str


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class User(UserBase):
    is_admin: bool = False


class ActivityBase(BaseModel):
    name: str
    description: str
    schedule: str
    max_participants: int


class Activity(ActivityBase):
    participants: list = []
