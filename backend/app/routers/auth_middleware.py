from fastapi import Request
from typing import Optional
from app.utils.logger import logger


class CookieTokenExtractor:
    # Cookie names
    ACCESS_TOKEN_COOKIE = "access_token"
    REFRESH_TOKEN_COOKIE = "refresh_token"
    MFA_TOKEN_COOKIE = "mfa_token"
    SETUP_TOKEN_COOKIE = "setup_token"
    
    @staticmethod
    def get_access_token(request: Request) -> Optional[str]:
        
        token = request.cookies.get(CookieTokenExtractor.ACCESS_TOKEN_COOKIE)
        
        if token and token.strip():
            logger.debug("Access token extracted from cookie")
            return token
        
        logger.debug("No access token in cookies")
        return None
    
    @staticmethod
    def get_refresh_token(request: Request) -> Optional[str]:
        return request.cookies.get(CookieTokenExtractor.REFRESH_TOKEN_COOKIE)
    
    @staticmethod
    def get_mfa_token(request: Request) -> Optional[str]:
        return request.cookies.get(CookieTokenExtractor.MFA_TOKEN_COOKIE)
    
    @staticmethod
    def get_setup_token(request: Request) -> Optional[str]:
        return request.cookies.get(CookieTokenExtractor.SETUP_TOKEN_COOKIE)
    
    @staticmethod
    def get_all_tokens(request: Request) -> dict:
        return {
            "access_token": CookieTokenExtractor.get_access_token(request),
            "refresh_token": CookieTokenExtractor.get_refresh_token(request),
            "mfa_token": CookieTokenExtractor.get_mfa_token(request),
            "setup_token": CookieTokenExtractor.get_setup_token(request),
        }


class CookieManager:
    @staticmethod
    def set_auth_cookies(
        response,
        access_token: str,
        refresh_token: str,
        access_exp_seconds: int,
        refresh_exp_seconds: int,
        secure: bool = True,
        domain: str = "",
        path: str = "/"
    ):
        # Access token cookie (shorter expiry)
        response.set_cookie(
            key=CookieTokenExtractor.ACCESS_TOKEN_COOKIE,
            value=access_token,
            max_age=access_exp_seconds,
            secure=secure,
            httponly=True,  
            samesite="lax", 
            path=path,
            domain=domain if domain else None,
        )
        
        logger.debug(f"Access token cookie set (expires in {access_exp_seconds}s)")
        
        response.set_cookie(
            key=CookieTokenExtractor.REFRESH_TOKEN_COOKIE,
            value=refresh_token,
            max_age=refresh_exp_seconds,
            secure=secure,
            httponly=True,
            samesite="lax",
            path=path,
            domain=domain if domain else None,
        )
        
        logger.debug(f"Refresh token cookie set (expires in {refresh_exp_seconds}s)")
    
    @staticmethod
    def set_mfa_cookie(
        response,
        mfa_token: str,
        exp_seconds: int = 900, 
        secure: bool = True,
        domain: str = "",
        path: str = "/"
    ):
        response.set_cookie(
            key=CookieTokenExtractor.MFA_TOKEN_COOKIE,
            value=mfa_token,
            max_age=exp_seconds,
            secure=secure,
            httponly=True,
            samesite="lax",
            path=path,
            domain=domain if domain else None,
        )
        
        logger.debug(f"MFA token cookie set (expires in {exp_seconds}s)")
    
    @staticmethod
    def set_setup_cookie(
        response,
        setup_token: str,
        exp_seconds: int = 1800,  
        secure: bool = True,
        domain: str = "",
        path: str = "/"
    ):
        response.set_cookie(
            key=CookieTokenExtractor.SETUP_TOKEN_COOKIE,
            value=setup_token,
            max_age=exp_seconds,
            secure=secure,
            httponly=True,
            samesite="lax",
            path=path,
            domain=domain if domain else None,
        )
        
        logger.debug(f"Setup token cookie set (expires in {exp_seconds}s)")
    
    @staticmethod
    def clear_auth_cookies(response, path: str = "/", domain: str = ""):
        cookies_to_clear = [
            CookieTokenExtractor.ACCESS_TOKEN_COOKIE,
            CookieTokenExtractor.REFRESH_TOKEN_COOKIE,
            CookieTokenExtractor.MFA_TOKEN_COOKIE,
            CookieTokenExtractor.SETUP_TOKEN_COOKIE,
        ]
        
        for cookie_name in cookies_to_clear:
            response.delete_cookie(
                key=cookie_name,
                path=path,
                domain=domain if domain else None,
            )
            logger.debug(f"Cleared cookie: {cookie_name}")
    
    @staticmethod
    def clear_specific_cookie(response, cookie_name: str, path: str = "/", domain: str = ""):
        response.delete_cookie(
            key=cookie_name,
            path=path,
            domain=domain if domain else None,
        )
        logger.debug(f"Cleared cookie: {cookie_name}")