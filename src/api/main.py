"""FastAPI application for Compliance Guardian AI."""

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from typing import Optional
import uvicorn

from .routes import (
    agents_router,
    scans_router,
    workflows_router,
    reports_router,
    remediation_router,
    health_router
)
from ..core.agent_runtime import AgentRuntime
from ..core.observability import ObservabilityManager
from ..utils.logger import get_logger
from ..utils.config import get_config

logger = get_logger(__name__)
config = get_config()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup
    logger.info("Starting Compliance Guardian AI application")
    
    # Initialize agent runtime
    app.state.agent_runtime = AgentRuntime(config.dict())
    await app.state.agent_runtime.initialize()
    
    # Initialize observability
    app.state.observability = ObservabilityManager(config.dict())
    
    logger.info("Application startup complete")
    
    yield
    
    # Shutdown
    logger.info("Shutting down Compliance Guardian AI application")
    await app.state.agent_runtime.shutdown()
    logger.info("Application shutdown complete")


# Create FastAPI app
app = FastAPI(
    title="Compliance Guardian AI",
    description="Autonomous Compliance & Privacy Guardian Multi-Agent System",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Include routers
app.include_router(health_router, prefix="/api/v1", tags=["health"])
app.include_router(agents_router, prefix="/api/v1", tags=["agents"])
app.include_router(scans_router, prefix="/api/v1", tags=["scans"])
app.include_router(workflows_router, prefix="/api/v1", tags=["workflows"])
app.include_router(reports_router, prefix="/api/v1", tags=["reports"])
app.include_router(remediation_router, prefix="/api/v1", tags=["remediation"])


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "Compliance Guardian AI",
        "version": "1.0.0",
        "documentation": "/docs",
        "health": "/api/v1/health"
    }


@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Handle HTTP exceptions."""
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail}
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """Handle general exceptions."""
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error"}
    )


# Lambda handler using Mangum
try:
    from mangum import Mangum
    lambda_handler = Mangum(app, lifespan="off")
except ImportError:
    # Mangum not available (local development)
    lambda_handler = None


if __name__ == "__main__":
    uvicorn.run(
        "src.api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_config=None
    )
