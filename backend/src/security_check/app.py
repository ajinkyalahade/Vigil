from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from security_check.ai_resolution import AnthropicClient, ExecutionService, ResolutionService
from security_check.api import router
from security_check.config import Settings, get_settings
from security_check.db import Database
from security_check.runner import ScanService, default_registry


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    project_root = Path(__file__).resolve().parents[3]
    db_path = settings.db_path if settings.db_path.is_absolute() else (project_root / settings.db_path)
    db = Database(path=db_path)
    db.init()

    app = FastAPI(title="Vigil API")

    origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    registry = default_registry()
    app.state.scan_service = ScanService(db=db, settings=settings, registry=registry)

    # Initialize AI resolution service if API key is provided
    if settings.anthropic_api_key and not settings.disable_ai_resolution:
        try:
            ai_client = AnthropicClient(
                api_key=settings.anthropic_api_key,
                model=settings.anthropic_model,
                max_tokens=settings.anthropic_max_tokens,
                timeout=settings.anthropic_timeout_seconds,
            )
            app.state.resolution_service = ResolutionService(
                db=db,
                client=ai_client,
                cache_ttl=settings.ai_resolution_cache_ttl,
            )
        except Exception as e:
            # Log error but don't fail app startup
            import logging
            logging.warning(f"Failed to initialize AI resolution service: {e}")
            app.state.resolution_service = None
    else:
        app.state.resolution_service = None

    app.state.execution_service = ExecutionService(db=db, settings=settings)

    app.include_router(router)
    return app


app = create_app()
