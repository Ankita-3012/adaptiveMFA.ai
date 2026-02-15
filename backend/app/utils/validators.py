import re
from typing import Optional
from pydantic import ValidationError, field_validator, BaseModel


def validate_email(email: str) -> bool:
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_password(password: str) -> tuple[bool, str]:
    """
    Validate password strength
    
    Requirements:
    - At least 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    
    return True, "Password is strong"


def validate_ip_address(ip: str) -> bool:
    """Validate IPv4 or IPv6 address"""
    # IPv4
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ipv4_pattern, ip):
        parts = ip.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    
    # IPv6 (simplified check)
    ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
    return bool(re.match(ipv6_pattern, ip))


def validate_device_fingerprint(fingerprint: str) -> bool:
    """Validate device fingerprint format (32 chars, alphanumeric)"""
    if not isinstance(fingerprint, str):
        return False
    return bool(re.match(r'^[a-zA-Z0-9]{32}$', fingerprint))


def validate_otp(code: str) -> bool:
    """Validate OTP code (6 digits)"""
    return bool(re.match(r'^\d{6}$', code))


class EmailValidator(BaseModel):
    """Pydantic validator for emails"""
    email: str
    
    @field_validator('email')
    @classmethod
    def validate_email_field(cls, v: str) -> str:
        if not validate_email(v):
            raise ValueError('Invalid email format')
        return v.lower()


class PasswordValidator(BaseModel):
    """Pydantic validator for passwords"""
    password: str
    
    @field_validator('password')
    @classmethod
    def validate_password_field(cls, v: str) -> str:
        is_valid, message = validate_password(v)
        if not is_valid:
            raise ValueError(message)
        return v