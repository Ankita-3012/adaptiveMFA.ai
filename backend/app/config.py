from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import ClassVar, List
from pydantic import Field,EmailStr


class Settings(BaseSettings):
    #app
    APP_NAME: str = "Login Anomaly Detection"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    #server
    SERVER_HOST: str 
    SERVER_PORT: int = 8001

    #database
    DATABASE_URL: str
    LOG_LEVEL: str = Field(default="INFO")
    LOG_FORMAT: str = (
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )

    #security
    SECRET_KEY: str
    ENCRYPTION_KEY: str
    ALGORITHM: str

    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    MFA_TOKEN_EXPIRE_MINUTES: int = 15
    SETUP_TOKEN_EXPIRE_MINUTES: int = 30

    #llm
    GROQ_API_KEY: str = ""
    GROQ_MODEL_NAME: str = "mixtral-8x7b-32768"

    EMBEDDING_MODEL: str = "all-MiniLM-L6-v2"

    #pinecone
    PINECONE_API_KEY: str = ""
    PINECONE_INDEX_NAME: str

    #cookies
    COOKIE_SECURE: bool = False  
    COOKIE_SAMESITE: str = "lax"  
    COOKIE_DOMAIN: str = ""
    COOKIE_PATH: str = "/"

    #ml
    ML_ANOMALY_DETECTION_ENABLED: bool = True

    MAIL_USERNAME: EmailStr
    MAIL_PASSWORD: str
    MAIL_FROM: EmailStr
    MAIL_PORT: int = 587
    MAIL_SERVER: str = "smtp.gmail.com"
    MAIL_TLS: bool = True
    MAIL_SSL: bool = False

    FRONTEND_URL: str = "http://localhost:3000"

    #cors
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
    ]

    #constants 
    RP_ID: ClassVar[str] = "adaptive-mfa.local"
    ORIGIN: ClassVar[str] = "http://localhost:3000"

    MODEL_PATH: str = "./app/trained_model/anomaly_model.pkl"
    ML_ANOMALY_DETECTION_ENABLED: bool = True
    RISK_THRESHOLD_LOW: float = 0.3
    RISK_THRESHOLD_HIGH: float = 0.7

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
        extra="allow",
    )


settings = Settings()
