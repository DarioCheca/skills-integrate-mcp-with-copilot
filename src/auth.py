"""
Authentication utilities for password hashing and user management
"""

import bcrypt
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict

# In-memory user database (will be replaced with SQLite in issue #8)
users_db: Dict = {}

# In-memory session store (will be replaced with SQLite in issue #8)
sessions: Dict = {}


def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()


def verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash"""
    return bcrypt.checkpw(password.encode(), hashed.encode())


def create_session_token() -> str:
    """Generate a secure session token"""
    return secrets.token_urlsafe(32)


def create_user(email: str, full_name: str, password: str, is_admin: bool = False) -> dict:
    """Create a new user"""
    if email in users_db:
        raise ValueError("User already exists")
    
    user = {
        "email": email,
        "full_name": full_name,
        "hashed_password": hash_password(password),
        "is_admin": is_admin,
        "created_at": datetime.now().isoformat()
    }
    users_db[email] = user
    return user


def authenticate_user(email: str, password: str) -> Optional[dict]:
    """Authenticate user by email and password"""
    user = users_db.get(email)
    if not user:
        return None
    
    if not verify_password(password, user["hashed_password"]):
        return None
    
    return user


def create_user_session(email: str) -> str:
    """Create a session for authenticated user"""
    token = create_session_token()
    sessions[token] = {
        "email": email,
        "created_at": datetime.now().isoformat(),
        "expires_at": (datetime.now() + timedelta(days=7)).isoformat()
    }
    return token


def get_session_user(token: str) -> Optional[str]:
    """Get user email from session token"""
    session = sessions.get(token)
    if not session:
        return None
    
    # Check if session expired
    expires_at = datetime.fromisoformat(session["expires_at"])
    if datetime.now() > expires_at:
        del sessions[token]
        return None
    
    return session["email"]


def invalidate_session(token: str) -> bool:
    """Logout user by invalidating session"""
    if token in sessions:
        del sessions[token]
        return True
    return False


def get_user_by_email(email: str) -> Optional[dict]:
    """Get user data by email"""
    return users_db.get(email)
