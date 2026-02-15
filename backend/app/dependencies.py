from fastapi import Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from app.database.connection import get_db
from app.models.user import User
from app.services.auth_service import AuthService
from app.routers.auth_middleware import CookieTokenExtractor


async def get_current_user(
    request: Request,
    db: Session = Depends(get_db)
) -> User:
    access_token = CookieTokenExtractor.get_access_token(request)
    
    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No access token found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user = AuthService.get_current_user(access_token, db)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return user