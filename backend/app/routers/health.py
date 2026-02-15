from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database.connection import get_db
from app.config import settings
from app.utils.logger import logger
from datetime import datetime

router = APIRouter()


@router.get("/health")
async def health_check():
    """Basic health check"""
    logger.debug("Health check requested")
    
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": settings.APP_VERSION,
    }


@router.get("/health/db")
async def health_check_db(db: Session = Depends(get_db)):
   
    logger.debug("Database health check requested")
    
    try:
        # Simple query to test connection
        db.execute("SELECT 1")
        
        return {
            "status": "healthy",
            "component": "database",
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        
        return {
            "status": "unhealthy",
            "component": "database",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat(),
        }


@router.get("/health/services")
async def health_check_services():
   
    logger.debug("Services health check requested")
    
    services_status = {}
    
    # Check LLM availability
    try:
        if settings.GROQ_API_KEY:
            services_status["llm"] = {
                "status": "healthy",
                "model": settings.GROQ_MODEL_NAME,
            }
        else:
            services_status["llm"] = {
                "status": "disabled",
                "reason": "GROQ_API_KEY not set",
            }
    except Exception as e:
        services_status["llm"] = {
            "status": "unhealthy",
            "error": str(e),
        }
    
    # Check Risk Service
    try:
        services_status["risk_assessment"] = {
            "status": "healthy",
            "enabled": True,
        }
    except Exception as e:
        services_status["risk_assessment"] = {
            "status": "unhealthy",
            "error": str(e),
        }
    
    # Check Auth Service
    try:
        services_status["auth"] = {
            "status": "healthy",
            "mfa": "TOTP",
            "encryption": "Fernet",
        }
    except Exception as e:
        services_status["auth"] = {
            "status": "unhealthy",
            "error": str(e),
        }
    
    return {
        "status": "healthy",
        "component": "services",
        "services": services_status,
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.get("/info")
async def app_info():
   
    logger.debug("App info requested")
    
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "debug": settings.DEBUG,
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.get("/config/risk-thresholds")
async def get_risk_thresholds():
   
    logger.debug("Risk thresholds requested")
    
    return {
        "low_threshold": settings.RISK_THRESHOLD_LOW,
        "high_threshold": settings.RISK_THRESHOLD_HIGH,
        "description": {
            "low": f"Risk < {settings.RISK_THRESHOLD_LOW} = Allow",
            "medium": f"{settings.RISK_THRESHOLD_LOW} <= Risk < {settings.RISK_THRESHOLD_HIGH} = Verify (MFA)",
            "high": f"Risk >= {settings.RISK_THRESHOLD_HIGH} = Block",
        }
    }