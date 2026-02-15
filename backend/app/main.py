"""
FastAPI Application - Login Anomaly Detection System
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from app.config import settings
from app.database.connection import engine, Base, init_db
from app.routers import auth, risk, health, sessions_router
from app.utils.logger import setup_logger, logger
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Setup logger
logger = setup_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events"""
    # Startup
    logger.info("="*60)
    logger.info("Starting Login Anomaly Detection System")
    logger.info("="*60)
    
    try:
        # Create database tables
        logger.info("Creating database tables...")
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created")
        
        # Load ML model
        logger.info("Loading ML models...")
        from app.services.anomaly_service import AnomalyService
        anomaly_service = AnomalyService()
        if anomaly_service.is_trained:
            logger.info("Anomaly detection model loaded")
        else:
            logger.warning("Anomaly detection model not trained")
            logger.info("Run: python -m app.ml.trainer")
        
        # Initialize RAG
        logger.info("Initializing RAG service...")
        from app.services.rag_service import RAGService
        rag_service = RAGService()
        stats = rag_service.get_collection_stats()
        logger.info(f"RAG initialized - Documents: {stats.get('total_documents', 0)}")
        
        # Initialize Embeddings
        logger.info("Initializing embedding model...")
        from app.services.embedding_service import EmbeddingService
        embedding_service = EmbeddingService()
        logger.info("Embedding model loaded")
        
        # Initialize LangGraph
        logger.info("Initializing LangGraph workflow...")
        from app.services.langgraph_service import LangGraphWorkflow
        workflow = LangGraphWorkflow(
            anomaly_service=anomaly_service,
            rag_service=rag_service,
            groq_api_key=settings.GROQ_API_KEY,
            groq_model_name=settings.GROQ_MODEL_NAME
        )
        logger.info("LangGraph workflow compiled")
        
        logger.info("="*60)
        logger.info("Application Ready!")
        logger.info("="*60)
        
        yield
        
    except Exception as e:
        logger.error(f"Startup error: {e}")
        raise
    
    finally:
        # Shutdown
        logger.info("="*60)
        logger.info("Shutting down application...")
        logger.info("="*60)


# Create FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    description="ML + RAG + LangGraph powered login anomaly detection system",
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],  
    allow_headers=["*"],
)


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "description": "Login anomaly detection with ML + RAG + LangGraph",
        "docs": "/docs",
        "health": "/health",
    }


# Include routers
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(risk.router, prefix="/api/risk", tags=["Risk Assessment"])
app.include_router(health.router, prefix="/api", tags=["Health"])
app.include_router(sessions_router.router,prefix="/api")


# Exception handlers
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions"""
    logger.warning(f"HTTP Exception: {exc.status_code} - {exc.detail}")
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail},
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions"""
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error"},
    )

@app.exception_handler(RateLimitExceeded)
async def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):
    logger.warning(f"Rate limit exceeded: {request.client.host}")
    return JSONResponse(
        status_code=429,
        content={"error": "Too many requests. Please slow down."},
    )


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host=settings.SERVER_HOST,
        port=settings.SERVER_PORT,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower(),
    )