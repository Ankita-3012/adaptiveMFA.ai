from slowapi import Limiter
from slowapi.util import get_remote_address
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime, timezone
from app.database.connection import get_db
from app.models import (
    RegisterRequest,
    LoginRequest,
    MFAVerifyRequest,
    RegenerateMFARequest,
    LogoutResponse,
    UserResponse,
    ForgotPasswordResponse,
    ForgotPasswordRequest,
    ResetPasswordRequest,
    ResetPasswordResponse
)
from app.models.user import User
from app.models.login_event import LoginEvent
from app.models.session import Session as DBSession
from app.services.auth_service import AuthService, AuthServiceError
from app.services.risk_service import RiskAssessmentService
from app.utils.logger import logger
from app.config import settings
from app.utils.tokens import verify_password_reset_token, create_password_reset_token
from app.utils.passwords import hash_password
from app.extensions.mail import send_email
from app.routers.auth_middleware import CookieManager, CookieTokenExtractor

router = APIRouter(tags=["Auth"])
limiter = Limiter(key_func=get_remote_address)

risk_service = RiskAssessmentService()


@router.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    summary="Register new user"
)
@limiter.limit("3/minute")
async def register(
    request: Request,
    payload: RegisterRequest,
    db: Session = Depends(get_db),
):
    try:
        success, msg, user, qr_uri, backup_codes, setup_token = (
            AuthService.register_user(
                email=payload.email,
                password=payload.password,
                db=db,
            )
        )

        if not success:
            logger.warning(f"Registration failed for {payload.email}: {msg}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=msg
            )

        logger.info(f"User registered: {payload.email}")

        response = JSONResponse(
            content={
                "message": "User registered successfully. Save backup codes securely!",
                "user": UserResponse.model_validate(user).model_dump(mode='json'),
                "qr_code_uri": qr_uri,
                "backup_codes": backup_codes,
            },
            status_code=status.HTTP_201_CREATED
        )

        CookieManager.set_setup_cookie(
            response,
            setup_token,
            exp_seconds=30 * 60,
            secure=settings.COOKIE_SECURE,
            domain=settings.COOKIE_DOMAIN,
            path=settings.COOKIE_PATH
        )

        return response

    except HTTPException:
        raise
    except AuthServiceError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Registration error: {e}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed"
        )


@router.post("/forgot-password", response_model=ForgotPasswordResponse)
@limiter.limit("3/minute")
async def forgot_password(
    request: Request,
    payload: ForgotPasswordRequest,
    db: Session = Depends(get_db)
):
    try:
        user = db.query(User).filter(User.email == payload.email.lower()).first()
        if not user:
            return ForgotPasswordResponse(
                message="If an account exists with this email, a reset link has been sent."
            )

        token = create_password_reset_token(user.email)
        reset_link = f"{settings.FRONTEND_URL}/reset-password?token={token}"

        await send_email(
            to_email=user.email,
            subject="Password Reset Request",
            body=f"Click the link to reset your password: {reset_link}"
        )

        logger.info(f"Password reset email sent to: {payload.email}")

        return ForgotPasswordResponse(
            message="If an account exists with this email, a reset link has been sent."
        )

    except Exception as e:
        logger.error(f"Forgot password error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process password reset"
        )


@router.post("/reset-password", response_model=ResetPasswordResponse)
@limiter.limit("3/minute")
async def reset_password(
    request: Request,
    payload: ResetPasswordRequest,
    db: Session = Depends(get_db)
):
    try:
        email = verify_password_reset_token(payload.token)
        if not email:
            raise HTTPException(status_code=400, detail="Invalid or expired token")

        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        user.password_hash = hash_password(payload.new_password)
        db.commit()

        logger.info(f"Password reset for: {email}")

        return ResetPasswordResponse(
            message="Password updated successfully"
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Reset password error: {e}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to reset password"
        )


@router.post(
    "/login",
    status_code=status.HTTP_200_OK,
    summary="Login with email and password"
)
@limiter.limit("5/minute")
async def login(
    request: Request,
    login_data: LoginRequest,
    db: Session = Depends(get_db),
):
    try:
        client_ip = request.client.host if request.client else "0.0.0.0"
        user_agent = request.headers.get("user-agent", "unknown")

        INVALID_FP = {"", "unknown", "unknown-device", "null", "undefined"}
        raw_fp = (login_data.device_fingerprint or "").strip()

        if raw_fp.lower() in INVALID_FP:
            import hashlib
            stable_seed = f"{user_agent}|{client_ip}"
            fingerprint = "srv_" + hashlib.sha256(stable_seed.encode()).hexdigest()
            fp_source = "server"
            logger.warning(
                f"No valid client fingerprint received — using deterministic "
                f"server fallback: {fingerprint[:16]}..."
            )
        else:
            fingerprint = raw_fp
            fp_source = "client"
            logger.info(f"Client fingerprint accepted: {fingerprint[:16]}...")

        resolved_location = login_data.location

        if client_ip and client_ip not in ("127.0.0.1", "::1", "0.0.0.0"):
            try:
                geo = risk_service.resolve_ip_location(client_ip)
                if geo:
                    resolved_location = geo
            except Exception as e:
                logger.warning(f"IP location resolution failed: {e}")

        if not resolved_location:
            resolved_location = "Unknown"

        success, msg, user = AuthService.login_user(
            login_data.email,
            login_data.password,
            db,
            device_fingerprint=fingerprint,
            ip_address=client_ip
        )

        if not success:
            logger.warning(f"Login failed for {login_data.email}: {msg}")

            if user:
                user.failed_login_attempts += 1
                db.commit()

            if getattr(user, "is_locked", False):
                msg = "Account is locked. Contact support."

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=msg
            )

        logger.info(f"User authenticated: {login_data.email}")

        risk_data = risk_service.assess_login(
            login_event={
                "ip_address": client_ip,
                "user_agent": user_agent,
                "device_fingerprint": fingerprint,
                "location": resolved_location,
                "typing_speed": login_data.typing_speed or 0.0,
                "key_interval": login_data.key_interval or 0.0,
                "key_hold": login_data.key_hold or 0.0,
                "location_latitude": login_data.location_latitude,
                "location_longitude": login_data.location_longitude,
                "location_city": login_data.location_city,
                "location_region": login_data.location_region,
                "location_country": login_data.location_country,
            },
            db=db,
            user=user
        )

        if fp_source == "server":
            device_known = False
            logger.info("Server-side fingerprint — device treated as unknown")
        else:
            existing_device = db.query(LoginEvent).filter(
                LoginEvent.user_id == user.id,
                LoginEvent.device_fingerprint == fingerprint,
                LoginEvent.user_action == "approved"
            ).first()
            device_known = existing_device is not None

        logger.info(f"Device known: {device_known} (fp_source={fp_source})")

        risk_score = risk_data.get("risk_score", 0.5)
        risk_level = risk_data.get("risk_level", "medium")
        location_metric = risk_data.get("location_metric", 0.0)
        impossible_travel = location_metric and location_metric > 900

        if impossible_travel:
            logger.warning(f"IMPOSSIBLE TRAVEL DETECTED: {location_metric:.2f} km/h")

        login_event = LoginEvent(
            user_id=user.id,
            ip_address=client_ip,
            device_fingerprint=fingerprint,
            user_agent=user_agent,
            location=resolved_location,
            location_latitude=login_data.location_latitude,
            location_longitude=login_data.location_longitude,
            location_city=login_data.location_city,
            location_region=login_data.location_region,
            location_country=login_data.location_country,
            location_metric=location_metric,
            risk_score=risk_score,
            risk_level=risk_level,
            anomaly_score=risk_data.get("anomaly_score", 0.5),
            behavior_risk=risk_data.get("behavior_risk"),
            device_known=device_known,
            device_last_seen_at=risk_data.get("last_seen"),
            mfa_required=risk_data.get("mfa_required", False),
            user_action="pending",
        )

        db.add(login_event)
        db.commit()

        logger.info(
            f"Login event saved — Risk: {risk_score:.2f} ({risk_level}), "
            f"Device: {fingerprint[:16]}... known={device_known}"
        )

        logger.info(
            f"MFA Decision: risk_level={risk_level}, "
            f"device_known={device_known}, "
            f"impossible_travel={impossible_travel}"
        )

        if risk_level == "low":
            logger.info(f"✅ LOW RISK → Direct login (no MFA)")

            access_token, access_jti, access_exp = AuthService.create_access_token(str(user.id))
            refresh_token, refresh_jti, refresh_exp = AuthService.create_refresh_token(str(user.id))

            AuthService.create_session(
                db, str(user.id), access_jti, access_exp,
                token_type="access",
                device_fingerprint=fingerprint,
                ip_address=client_ip
            )
            AuthService.create_session(
                db, str(user.id), refresh_jti, refresh_exp,
                token_type="refresh"
            )

            login_event.user_action = "approved"
            db.commit()

            logger.info(f"✅ LOGIN SUCCESSFUL (LOW RISK): {login_data.email}")

            user_data = UserResponse.model_validate(user).model_dump(mode='json')

            response = JSONResponse(
                content={
                    "message": "Login successful",
                    "user": user_data,
                    "mfa_required": False,
                    "risk_score": risk_score,
                    "risk_level": risk_level,
                    "device_known": device_known,
                    "instructions": "Welcome back! Low-risk login.",
                }
            )

            CookieManager.set_auth_cookies(
                response,
                access_token,
                refresh_token,
                access_exp_seconds=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                refresh_exp_seconds=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600,
                secure=settings.COOKIE_SECURE,
                domain=settings.COOKIE_DOMAIN,
                path=settings.COOKIE_PATH
            )

            return response

        mfa_token, mfa_jti, mfa_exp = AuthService.create_mfa_token(str(user.id))

        AuthService.create_session(
            db, str(user.id), mfa_jti, mfa_exp,
            token_type="mfa"
        )

        db.commit()

        if risk_level == "high":
            logger.info(
                f"HIGH RISK → Require TOTP + geolocation check "
                f"(impossible_travel={impossible_travel})"
            )

            logger.warning(
                f"HIGH RISK LOGIN for {login_data.email}: "
                f"Location={resolved_location}, "
                f"Impossible Travel={impossible_travel}, "
                f"Device Known={device_known}"
            )

            if impossible_travel:
                instruction = (
                    f"Very unusual login detected (impossible travel: {location_metric:.0f} km/h). "
                    f"Please verify with MFA immediately."
                )
            elif device_known:
                instruction = (
                    f"High-risk login from known device. "
                    f"Location: {resolved_location}. Please verify with MFA."
                )
            else:
                instruction = (
                    f"High-risk login from new location. "
                    f"Location: {resolved_location}. Please verify with MFA."
                )
        else:
            logger.info(f"MEDIUM RISK → Require TOTP (always)")
            instruction = "Medium-risk login detected. Please verify with MFA."

        logger.info(f"MFA REQUIRED: {login_data.email} — Risk: {risk_score:.2f}")

        user_data = UserResponse.model_validate(user).model_dump(mode='json')

        response = JSONResponse(
            content={
                "message": "Password verified - MFA required",
                "user": user_data,
                "mfa_required": True,
                "login_event_id": str(login_event.id),
                "risk_score": risk_score,
                "risk_level": risk_level,
                "device_known": device_known,
                "instructions": instruction,
            }
        )

        CookieManager.set_mfa_cookie(
            response,
            mfa_token,
            exp_seconds=settings.MFA_TOKEN_EXPIRE_MINUTES * 60,
            secure=settings.COOKIE_SECURE,
            domain=settings.COOKIE_DOMAIN,
            path=settings.COOKIE_PATH
        )

        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed"
        )


@router.post(
    "/verify-mfa",
    status_code=status.HTTP_200_OK,
    summary="Verify MFA code and get tokens"
)
@limiter.limit("5/minute")
async def verify_mfa(
    request: Request,
    payload: MFAVerifyRequest,
    db: Session = Depends(get_db),
):
    try:
        mfa_token = CookieTokenExtractor.get_mfa_token(request)

        if not mfa_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="No MFA token found"
            )

        success, token_payload = AuthService.verify_token(
            mfa_token,
            token_type="mfa",
        )

        if not success or not token_payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid MFA token"
            )

        consumed = db.query(DBSession).filter(
            DBSession.jti == token_payload["jti"],
            DBSession.is_active.is_(True)
        ).update({"is_active": False})
        db.flush()

        if not consumed:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="MFA token already used"
            )

        user = db.query(User).filter(User.id == token_payload["sub"]).first()
        if not user or not user.mfa_enabled:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid MFA session"
            )

        if not AuthService.verify_mfa_code(user.mfa_secret, payload.code):
            logger.warning(f"MFA verify: Invalid code for {user.email}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid TOTP code"
            )

        access_token, access_jti, access_exp = AuthService.create_access_token(str(user.id))
        refresh_token, refresh_jti, refresh_exp = AuthService.create_refresh_token(str(user.id))

        AuthService.create_session(db, str(user.id), access_jti, access_exp, token_type="access")
        AuthService.create_session(db, str(user.id), refresh_jti, refresh_exp, token_type="refresh")

        login_event = db.query(LoginEvent).filter(
            LoginEvent.user_id == user.id,
            LoginEvent.user_action == "pending"
        ).order_by(LoginEvent.timestamp.desc()).first()

        if login_event:
            logger.info(
                f"Approving login event {login_event.id} "
                f"(device={login_event.device_fingerprint[:16]}..., "
                f"timestamp={login_event.timestamp})"
            )
            login_event.user_action = "approved"
            login_event.device_last_seen_at = datetime.now(timezone.utc)
            logger.info(f"LoginEvent {login_event.id} marked APPROVED after MFA")
        else:
            logger.warning(f"No pending login event found for user {user.id}")

        db.commit()

        logger.info(f"MFA verified for: {user.email}")

        user_data = UserResponse.model_validate(user).model_dump(mode='json')

        response = JSONResponse(
            content={
                "message": "MFA verification successful",
                "user": user_data,
            }
        )

        CookieManager.set_auth_cookies(
            response,
            access_token,
            refresh_token,
            access_exp_seconds=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            refresh_exp_seconds=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600,
            secure=settings.COOKIE_SECURE,
            domain=settings.COOKIE_DOMAIN,
            path=settings.COOKIE_PATH
        )

        CookieManager.clear_specific_cookie(
            response,
            "mfa_token",
            path=settings.COOKIE_PATH,
            domain=settings.COOKIE_DOMAIN
        )

        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"MFA verification error: {e}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="MFA verification failed"
        )


@router.post(
    "/regenerate-mfa",
    status_code=status.HTTP_200_OK,
    summary="Regenerate MFA setup token"
)
async def regenerate_mfa_token(
    payload: RegenerateMFARequest,
    db: Session = Depends(get_db),
):
    try:
        user = db.query(User).filter(User.email == payload.email.lower()).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        if not AuthService.verify_password(payload.password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid password"
            )

        success, msg, token = AuthService.regenerate_setup_token(payload.email, db)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=msg
            )

        logger.info(f"MFA token regenerated for: {user.email}")

        response = JSONResponse(
            content={
                "message": msg,
            }
        )

        CookieManager.set_setup_cookie(
            response,
            token,
            exp_seconds=30 * 60,
            secure=settings.COOKIE_SECURE,
            domain=settings.COOKIE_DOMAIN,
            path=settings.COOKIE_PATH
        )

        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"MFA regeneration error: {e}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="MFA regeneration failed"
        )


@router.post(
    "/logout",
    response_model=LogoutResponse,
    status_code=status.HTTP_200_OK,
    summary="Logout and revoke token"
)
async def logout(
    request: Request,
    db: Session = Depends(get_db),
):
    try:
        access_token = CookieTokenExtractor.get_access_token(request)

        if not access_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="No token found"
            )

        if not AuthService.revoke_token(access_token, db):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token"
            )

        logger.info("User logged out successfully")

        response = JSONResponse(
            content={"message": "Logged out successfully"}
        )

        CookieManager.clear_auth_cookies(
            response,
            path=settings.COOKIE_PATH,
            domain=settings.COOKIE_DOMAIN
        )

        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Logout error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout failed"
        )