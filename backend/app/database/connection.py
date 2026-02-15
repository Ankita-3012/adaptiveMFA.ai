from sqlalchemy import create_engine, event, pool
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import NullPool, QueuePool
from app.config import settings
from app.database.base import Base
import logging
from typing import Generator

logger = logging.getLogger(__name__)

# Create engine with production settings 
if settings.DEBUG:
    engine = create_engine(
        settings.DATABASE_URL,
        echo=True,
        poolclass=NullPool,
        future=True,
    )
else:
    engine = create_engine(
        settings.DATABASE_URL,
        poolclass=QueuePool,
        pool_size=20,
        max_overflow=40,
        pool_pre_ping=True,  
        pool_recycle=3600,  
        echo=False,
        future=True,
    )

# Session factory
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    future=True
)


@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    if "postgresql" in settings.DATABASE_URL.lower():
        cursor = dbapi_connection.cursor()
        cursor.execute("SET SESSION TIMEZONE TO 'UTC'")
        cursor.close()


def init_db():
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created/verified")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    except Exception as e:
        logger.error(f"Database session error: {e}")
        db.rollback()
        raise
    finally:
        db.close()


def close_db():
    try:
        engine.dispose()
        logger.info("Database connections closed")
    except Exception as e:
        logger.error(f"Error closing database: {e}")