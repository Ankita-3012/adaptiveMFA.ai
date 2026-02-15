from itsdangerous import URLSafeTimedSerializer
from app.config import settings

serializer = URLSafeTimedSerializer(settings.SECRET_KEY)

def create_password_reset_token(email: str) -> str:
    """Generate a timed token for password reset"""
    return serializer.dumps(email, salt="password-reset-salt")

def verify_password_reset_token(token: str, max_age=900) -> str | None:
    """Verify token and return email if valid (15 minutes default)"""
    from itsdangerous import BadSignature, SignatureExpired
    try:
        email = serializer.loads(token, salt="password-reset-salt", max_age=max_age)
        return email
    except (BadSignature, SignatureExpired):
        return None
