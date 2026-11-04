from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, status
from fastapi.responses import JSONResponse

from controlplane_api.exceptions import ForbiddenException, UnauthorizedException
from controlplane_api.logging import configure_logging
from controlplane_api.config import settings
from api.infrastructure.persistence.db_session import configure_session_maker
from controlplane_api.service_cors import add_optional_service_cors
from controlplane_api.health import router as health_router
from controlplane_api.version import router as version_router
from controlplane_db.session import normalize_database_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from api_keys_service.middleware import ApiKeysDbMiddleware
from api_keys_service.routes import router as api_keys_router


def create_app() -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        configure_logging()
        engine = create_async_engine(normalize_database_url(settings.database_url))
        maker = async_sessionmaker(engine, expire_on_commit=False, autoflush=False)
        configure_session_maker(maker)
        app.state.async_engine = engine
        yield
        await engine.dispose()

    app = FastAPI(
        lifespan=lifespan,
        title="(s)panopticon API Keys Service",
        description="Tenant-scoped API keys for integrations.",
        version="0.1.0",
    )

    @app.exception_handler(UnauthorizedException)
    async def _unauthorized(_, ex: UnauthorizedException) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": ex.message},
        )

    @app.exception_handler(ForbiddenException)
    async def _forbidden(_, ex: ForbiddenException) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"error": ex.message},
        )

    app.add_middleware(ApiKeysDbMiddleware)
    app.include_router(health_router, prefix="/api/v1")
    app.include_router(version_router)
    app.include_router(api_keys_router, prefix="/api/v1")
    add_optional_service_cors(app, env_var="API_KEYS_SERVICE_CORS_ORIGINS")
    from controlplane_api.metrics import install_http_metrics

    install_http_metrics(app)
    return app


app = create_app()
