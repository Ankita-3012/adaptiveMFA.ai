from datetime import datetime, timedelta, timezone as tz
from typing import Dict, Optional, Tuple, Any
from uuid import uuid4
import json
import bcrypt
import pyotp
from cryptography.fernet import Fernet, InvalidToken
from jose import jwt, JWTError
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError, IntegrityError

from app.config import settings
from app.models.user import User
from app.models.session import Session as DBSession
from app.utils.logger import logger
from app.utils.validators import validate_email, validate_password

# Initialize encryption
try:
    fernet = Fernet(settings.ENCRYPTION_KEY.encode() if isinstance(settings.ENCRYPTION_KEY, str) else settings.ENCRYPTION_KEY)
except Exception as e:
    logger.error(f"Failed to initialize encryption: {e}")
    raise


class AuthServiceError(Exception):
    """Auth service custom exception"""
    pass


class AuthService:
    
    #Password Management

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password with bcrypt (12 rounds)"""
        try:
            salt = bcrypt.gensalt(rounds=12)
            return bcrypt.hashpw(password.encode(), salt).decode()
        except Exception as e:
            logger.error(f"Password hashing failed: {e}")
            raise AuthServiceError("Password hashing failed")

    @staticmethod
    def verify_password(plain: str, hashed: str) -> bool:
        """Verify password against hash"""
        try:
            return bcrypt.checkpw(plain.encode(), hashed.encode())
        except Exception as e:
            logger.warning(f"Password verification error: {e}")
            return False

   #TOTP MFA Management

    @staticmethod
    def encrypt_totp_secret(secret: str) -> str:
        """Encrypt TOTP secret for secure storage in database"""
        try:
            encrypted = fernet.encrypt(secret.encode())
            return encrypted.decode() if isinstance(encrypted, bytes) else encrypted
        except Exception as e:
            logger.error(f"TOTP encryption failed: {e}")
            raise AuthServiceError("TOTP encryption failed")

    @staticmethod
    def decrypt_totp_secret(encrypted_secret: str) -> str:
        """Decrypt TOTP secret from database storage"""
        try:
            decrypted = fernet.decrypt(
                encrypted_secret.encode() if isinstance(encrypted_secret, str) else encrypted_secret
            )
            return decrypted.decode() if isinstance(decrypted, bytes) else decrypted
        except InvalidToken:
            logger.error("Invalid TOTP secret token")
            raise AuthServiceError("Invalid TOTP secret")
        except Exception as e:
            logger.error(f"TOTP decryption failed: {e}")
            raise AuthServiceError("TOTP decryption failed")

    @staticmethod
    def build_totp_uri(email: str, secret: str) -> str:
        """Build TOTP provisioning URI for QR code generation"""
        try:
            totp = pyotp.TOTP(secret)
            return totp.provisioning_uri(
                name=email,
                issuer_name=settings.APP_NAME
            )
        except Exception as e:
            logger.error(f"TOTP URI generation failed: {e}")
            raise AuthServiceError("TOTP URI generation failed")

    @staticmethod
    def verify_mfa_code(encrypted_secret: str, code: str, valid_window: int = 1) -> bool:
        """Verify TOTP code against encrypted secret"""
        try:
            secret = AuthService.decrypt_totp_secret(encrypted_secret)
            totp = pyotp.TOTP(secret)
            return totp.verify(code, valid_window=valid_window)
        except Exception as e:
            logger.warning(f"MFA verification failed: {e}")
            return False

    # JWT Token Management

    @staticmethod
    def _encode_jwt(payload: dict) -> str:
        """Encode JWT token"""
        try:
            return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        except Exception as e:
            logger.error(f"JWT encoding failed: {e}")
            raise AuthServiceError("JWT encoding failed")

    @staticmethod
    def _build_payload(
        user_id: str,
        token_type: str,
        expires_at: datetime,
        jti: str
    ) -> dict:
        """Build JWT payload"""
        return {
            "sub": user_id,
            "jti": jti,
            "type": token_type,
            "exp": expires_at,
            "iat": datetime.now(tz.utc)
        }

    @staticmethod
    def create_access_token(user_id: str) -> Tuple[str, str, datetime]:
        jti = uuid4().hex
        exp = datetime.now(tz.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        token = AuthService._encode_jwt(
            AuthService._build_payload(user_id, "access", exp, jti)
        )
        logger.debug(f"Access token created for user {user_id}")
        return token, jti, exp

    @staticmethod
    def create_refresh_token(user_id: str) -> Tuple[str, str, datetime]:
        jti = uuid4().hex
        exp = datetime.now(tz.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        token = AuthService._encode_jwt(
            AuthService._build_payload(user_id, "refresh", exp, jti)
        )
        logger.debug(f"Refresh token created for user {user_id}")
        return token, jti, exp

    @staticmethod
    def create_mfa_token(user_id: str) -> Tuple[str, str, datetime]:
        jti = uuid4().hex
        exp = datetime.now(tz.utc) + timedelta(minutes=settings.MFA_TOKEN_EXPIRE_MINUTES)
        token = AuthService._encode_jwt(
            AuthService._build_payload(user_id, "mfa", exp, jti)
        )
        logger.debug(f"MFA token created for user {user_id}")
        return token, jti, exp

    @staticmethod
    def create_setup_token(user_id: str) -> Tuple[str, str, datetime]:
        jti = uuid4().hex
        exp = datetime.now(tz.utc) + timedelta(minutes=settings.SETUP_TOKEN_EXPIRE_MINUTES)
        token = AuthService._encode_jwt(
            AuthService._build_payload(user_id, "setup", exp, jti)
        )
        logger.debug(f"Setup token created for user {user_id}")
        return token, jti, exp

    @staticmethod
    def verify_token(token: str, token_type: str) -> Tuple[bool, Optional[dict]]:
        try:
            payload = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=[settings.ALGORITHM]
            )
            
            # Verify token type matches expected
            if payload.get("type") != token_type:
                logger.warning(
                    f"Token type mismatch. Expected {token_type}, got {payload.get('type')}"
                )
                return False, None
            
            logger.debug(f"Token verified: type={token_type}")
            return True, payload
            
        except JWTError as e:
            logger.debug(f"JWT verification failed: {e}")
            return False, None
        except Exception as e:
            logger.error(f"Token verification error: {e}")
            return False, None

    #User extraction from cookie
    @staticmethod
    def get_current_user(token: str, db: Session) -> Optional[User]:
        try:
            success, payload = AuthService.verify_token(token, "access")
            if not success or not payload:
                logger.warning("Invalid or expired access token")
                return None
            
            user = db.query(User).filter(User.id == payload["sub"]).first()
            if not user:
                logger.warning(f"User not found for token: {payload['sub']}")
                return None
            
            return user
            
        except Exception as e:
            logger.error(f"Get current user error: {e}")
            return None

    #Session Management 
    @staticmethod
    def create_session(
        db: Session,
        user_id: str,
        jti: str,
        expires_at: datetime,
        token_type: str = "access",
        device_fingerprint: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> DBSession:
        try:
            session = DBSession(
                id=uuid4(),
                user_id=user_id,
                jti=jti,
                token_type=token_type,
                is_active=True,
                expires_at=expires_at,
                device_fingerprint=device_fingerprint,
                ip_address=ip_address,
            )
            db.add(session)
            db.flush()
            logger.debug(f"Session created: {session.id} for user {user_id} (type={token_type})")
            return session
            
        except IntegrityError as e:
            db.rollback()
            logger.error(f"Session creation integrity error: {e}")
            raise AuthServiceError("Session creation failed - duplicate token")
        except SQLAlchemyError as e:
            db.rollback()
            logger.error(f"Session creation failed: {e}")
            raise AuthServiceError("Session creation failed")

    @staticmethod
    def validate_session(db: Session, jti: str) -> bool:
        """Validate that a session is active and not expired"""
        try:
            session = db.query(DBSession).filter(
                DBSession.jti == jti,
                DBSession.is_active.is_(True),
                DBSession.expires_at > datetime.now(tz.utc)
            ).first()
            return session is not None
        except Exception as e:
            logger.error(f"Session validation error: {e}")
            return False

    @staticmethod
    def consume_token(db: Session, jti: str) -> bool:
        try:
            updated = db.query(DBSession).filter(
                DBSession.jti == jti,
                DBSession.is_active.is_(True)
            ).update({"is_active": False})
            db.commit()
            
            if updated > 0:
                logger.debug(f"Token consumed: {jti}")
                return True
            
            logger.warning(f"Token not found or already consumed: {jti}")
            return False
            
        except SQLAlchemyError as e:
            db.rollback()
            logger.error(f"Token consumption failed: {e}")
            return False

    @staticmethod
    def revoke_token(token: str, db: Session) -> bool:
        try:
            success, payload = AuthService.verify_token(token, "access")
            if not success or not payload:
                logger.warning("Revoke: Invalid or expired token")
                return False

            updated = db.query(DBSession).filter(
                DBSession.jti == payload["jti"],
                DBSession.is_active.is_(True)
            ).update({"is_active": False})

            db.commit()
            
            if updated > 0:
                logger.debug(f"Token revoked: {payload['jti']}")
                return True
            
            logger.warning(f"Token not found or already revoked: {payload['jti']}")
            return False
            
        except SQLAlchemyError as e:
            db.rollback()
            logger.error(f"Token revocation failed: {e}")
            return False

    #User Management
    @staticmethod
    def register_user(
        email: str,
        password: str,
        db: Session
    ) -> Tuple[bool, str, Optional[User], Optional[str], Optional[list], Optional[str]]:
        # Validate inputs
        if not validate_email(email):
            logger.warning(f"Registration: Invalid email format: {email}")
            return False, "Invalid email format", None, None, None, None

        valid, msg = validate_password(password)
        if not valid:
            logger.warning(f"Registration: Password validation failed: {msg}")
            return False, msg, None, None, None, None

        # Check if email already exists
        existing_user = db.query(User).filter(User.email == email.lower()).first()
        if existing_user:
            logger.warning(f"Registration: Email already registered: {email}")
            return False, "Email already registered", None, None, None, None

        try:
            # Generate TOTP secret
            secret = pyotp.random_base32()
            encrypted_secret = AuthService.encrypt_totp_secret(secret)

            # Generate backup codes
            backup_codes = [uuid4().hex[:8] for _ in range(5)]
            hashed_codes = [AuthService.hash_password(c) for c in backup_codes]

            # Create user
            user = User(
                id=uuid4(),
                email=email.lower(),
                password_hash=AuthService.hash_password(password),
                is_active=True,
                is_verified=False,
                mfa_enabled=False,
                mfa_secret=encrypted_secret,
                backup_codes=json.dumps(hashed_codes),
            )

            db.add(user)
            db.flush()

            # Create setup token (for MFA setup)
            setup_token, jti, exp = AuthService.create_setup_token(str(user.id))
            
            # Create session record
            AuthService.create_session(
                db, 
                str(user.id), 
                jti, 
                exp, 
                token_type="setup"
            )

            db.commit()

            logger.info(f"User registered: {email}")
            qr_uri = AuthService.build_totp_uri(email, secret)

            return True, "User registered successfully", user, qr_uri, backup_codes, setup_token

        except IntegrityError as e:
            db.rollback()
            logger.error(f"Registration: Integrity error: {e}")
            return False, "Email already registered", None, None, None, None
        except SQLAlchemyError as e:
            db.rollback()
            logger.error(f"Registration: Database error: {e}")
            return False, "Registration failed", None, None, None, None
        except Exception as e:
            db.rollback()
            logger.error(f"Registration: Unexpected error: {e}")
            return False, "Registration failed", None, None, None, None

    @staticmethod
    def login_user(
        email: str,
        password: str,
        db: Session,
        device_fingerprint: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> Tuple[bool, str, Optional[User]]:
        
        try:
            user = db.query(User).filter(User.email == email.lower()).first()

            # Check password
            if not user or not AuthService.verify_password(password, user.password_hash):
                logger.warning(f"Login failed: Invalid credentials for {email}")
                return False, "Invalid credentials", None

            # Check if account is locked
            if getattr(user, "is_locked", False):
                logger.warning(f"Login failed: Account locked: {email}")
                return False, "Account is locked. Contact support.", None

            # Check if account is active
            if not getattr(user, "is_active", True):
                logger.warning(f"Login failed: User inactive: {email}")
                return False, "User account is inactive", None

            # Check if email is verified
            if not getattr(user, "is_verified", False):
                logger.warning(f"Login failed: Email not verified: {email}")
                return False, "Email not verified", None

            # Update last login
            user.last_login_at = datetime.now(tz.utc)
            user.failed_login_attempts = 0
            db.commit()

            logger.info(f"User login successful: {email}")
            return True, "Login successful", user

        except SQLAlchemyError as e:
            logger.error(f"Login: Database error: {e}")
            return False, "Login failed", None
        except Exception as e:
            logger.error(f"Login: Unexpected error: {e}")
            return False, "Login failed", None

    @staticmethod
    def regenerate_setup_token(email: str, db: Session) -> Tuple[bool, str, Optional[str]]:
        try:
            user = db.query(User).filter(User.email == email.lower()).first()

            if not user:
                logger.warning(f"Regenerate: User not found: {email}")
                return False, "User not found", None

            if user.mfa_enabled:
                logger.warning(f"Regenerate: MFA already enabled for {email}")
                return False, "MFA is already enabled", None

            # Create new setup token
            setup_token, jti, exp = AuthService.create_setup_token(str(user.id))
            
            # Create session record
            AuthService.create_session(
                db, 
                str(user.id), 
                jti, 
                exp, 
                token_type="setup"
            )
            
            db.commit()

            logger.info(f"Setup token regenerated for: {email}")
            return True, "Setup token generated", setup_token

        except SQLAlchemyError as e:
            db.rollback()
            logger.error(f"Regenerate: Database error: {e}")
            return False, "Failed to generate setup token", None
        except Exception as e:
            db.rollback()
            logger.error(f"Regenerate: Unexpected error: {e}")
            return False, "Failed to generate setup token", None

    # Behavior Profile Management
    @staticmethod
    def update_behavior_profile(
        user: User,
        metrics: Dict[str, float],
        db: Session
    ) -> bool: 
        try:
            # Load existing profile or create new
            profile = json.loads(user.behavior_profile) if user.behavior_profile else {
                "typing_speed": 0.0,
                "key_interval": 0.0,
                "key_hold": 0.0,
                "samples": 0,
                "last_updated": None
            }

            n = profile.get("samples", 0)

            # Rolling average with rounding
            profile["typing_speed"] = round(
                (profile.get("typing_speed", 0.0) * n + metrics.get("typing_speed", 0.0)) / (n + 1), 3
            )
            profile["key_interval"] = round(
                (profile.get("key_interval", 0.0) * n + metrics.get("key_interval", 0.0)) / (n + 1), 3
            )
            profile["key_hold"] = round(
                (profile.get("key_hold", 0.0) * n + metrics.get("key_hold", 0.0)) / (n + 1), 3
            )
            profile["samples"] = n + 1
            profile["last_updated"] = datetime.now(tz.utc).isoformat()

            user.behavior_profile = json.dumps(profile)
            db.commit()

            logger.debug(f"Behavior profile updated for user {user.id} (samples={profile['samples']})")
            return True

        except SQLAlchemyError as e:
            db.rollback()
            logger.error(f"Behavior profile update failed: {e}")
            return False
        except Exception as e:
            db.rollback()
            logger.error(f"Behavior profile update error: {e}")
            return False
