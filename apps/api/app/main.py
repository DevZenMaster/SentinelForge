"""SentinelForge FastAPI Application Entrypoint.

Provides the application factory, lifespan management, structured logging,
correlation ID tracking, restricted CORS policies, and standardized error envelopes.
"""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.v1 import api_v1_router
from app.core.config import settings
from app.core.logging import setup_logging
from app.core.middleware import RequestCorrelationMiddleware
from app.db.session import engine

# Initialize structured logging subsystem
logger = setup_logging(debug=settings.DEBUG)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    """Application lifespan context managing startup and graceful shutdown."""
    logger.info(
        f"Starting {settings.PROJECT_NAME} API in [{settings.ENVIRONMENT}] environment.",
        extra={"extra_fields": {"environment": settings.ENVIRONMENT, "debug": settings.DEBUG}},
    )
    yield
    logger.info("Shutting down SentinelForge API. Disposing database connection pool.")
    await engine.dispose()


def create_app() -> FastAPI:
    """Application factory for SentinelForge API."""
    app = FastAPI(
        title=settings.PROJECT_NAME,
        version="0.1.0",
        description="Production-style lightweight SIEM API foundation.",
        docs_url="/docs" if settings.ENVIRONMENT != "production" else None,
        redoc_url="/redoc" if settings.ENVIRONMENT != "production" else None,
        openapi_url=f"{settings.API_V1_STR}/openapi.json"
        if settings.ENVIRONMENT != "production"
        else None,
        lifespan=lifespan,
    )

    # 1. Add Request Correlation and Access Logging Middleware
    app.add_middleware(RequestCorrelationMiddleware)

    # 2. Add CORS Middleware (Restricted to configured origins; never wildcard with credentials)
    if settings.BACKEND_CORS_ORIGINS:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.BACKEND_CORS_ORIGINS,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type", "X-Request-ID", "X-Correlation-ID"],
            expose_headers=["X-Request-ID"],
            max_age=600,
        )

    # 3. Mount API v1 Routers
    app.include_router(api_v1_router, prefix=settings.API_V1_STR)

    # 4. Standardized Exception Handlers
    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        request_id = getattr(request.state, "request_id", "unknown")
        error_code = "HTTP_ERROR"
        if exc.status_code == status.HTTP_401_UNAUTHORIZED:
            error_code = "UNAUTHORIZED"
        elif exc.status_code == status.HTTP_403_FORBIDDEN:
            error_code = "FORBIDDEN"
        elif exc.status_code == status.HTTP_404_NOT_FOUND:
            error_code = "NOT_FOUND"
        elif exc.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
            error_code = "RATE_LIMIT_EXCEEDED"

        return JSONResponse(
            status_code=exc.status_code,
            content={
                "data": None,
                "meta": {
                    "timestamp": datetime.now(UTC).isoformat(),
                    "request_id": str(request_id),
                },
                "error": {
                    "code": error_code,
                    "message": str(exc.detail),
                    "details": None,
                },
            },
            headers={"X-Request-ID": str(request_id)},
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        request_id = getattr(request.state, "request_id", "unknown")
        # Format validation errors safely without raw user objects
        sanitized_errors: list[dict[str, Any]] = []
        for err in exc.errors():
            loc = " -> ".join(str(item) for item in err.get("loc", []))
            sanitized_errors.append({"field": loc, "issue": err.get("msg", "Invalid value")})

        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "data": None,
                "meta": {
                    "timestamp": datetime.now(UTC).isoformat(),
                    "request_id": str(request_id),
                },
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": "The submitted payload failed schema validation.",
                    "details": sanitized_errors,
                },
            },
            headers={"X-Request-ID": str(request_id)},
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        request_id = getattr(request.state, "request_id", "unknown")
        logger.critical(
            f"Unhandled exception on {request.method} {request.url.path}: {exc}",
            exc_info=True,
            extra={"request_id": request_id},
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "data": None,
                "meta": {
                    "timestamp": datetime.now(UTC).isoformat(),
                    "request_id": str(request_id),
                },
                "error": {
                    "code": "INTERNAL_SERVER_ERROR",
                    "message": (
                        "An unexpected internal server error occurred. "
                        "Please contact the SOC administrator."
                    ),
                    "details": None,
                },
            },
            headers={"X-Request-ID": str(request_id)},
        )

    return app


app = create_app()
