# core/ui/web_api.py
# DRAKBEN — Web UI Backend (FastAPI)
# REST API for dashboard, real-time events via SSE, and agent control.
# Inspired by PentAGI's React + Go REST/GraphQL architecture.

"""FastAPI-based web API for DRAKBEN.

Endpoints:
  GET  /api/v1/status          — Agent & system status
  GET  /api/v1/events          — SSE stream of real-time events
  GET  /api/v1/state           — Current AgentState snapshot
  GET  /api/v1/plan            — Current plan with step statuses
  GET  /api/v1/metrics         — Observability metrics
  GET  /api/v1/traces          — Recent trace spans
  GET  /api/v1/knowledge       — Knowledge graph stats
  GET  /api/v1/knowledge/entities — Knowledge graph entities
  POST /api/v1/agent/start     — Start autonomous scan
  POST /api/v1/agent/stop      — Stop agent
  POST /api/v1/agent/approve   — Approve pending action

Run::

    uvicorn core.ui.web_api:create_app --host 0.0.0.0 --port 8484
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

logger = logging.getLogger(__name__)


def create_app():
    """Create and configure the FastAPI application.

    Uses lazy import so the module can be imported even when
    ``fastapi`` / ``uvicorn`` are not installed (graceful degradation).
    """
    try:
        from fastapi import FastAPI
        from fastapi.middleware.cors import CORSMiddleware
    except ImportError:
        logger.warning(
            "FastAPI not installed. Web UI unavailable. "
            "Install with: pip install fastapi uvicorn",
        )
        return None

    app = FastAPI(
        title="DRAKBEN API",
        description="AI-Powered Penetration Testing Framework — REST API",
        version="1.0.0",
    )

    # CORS for frontend
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    _register_system_endpoints(app)
    _register_event_endpoints(app)
    _register_agent_endpoints(app)

    return app


def _register_system_endpoints(app) -> None:
    """Register system status and data endpoints."""

    @app.get("/api/v1/status")
    async def get_status() -> dict[str, Any]:
        """Get system and agent status."""
        return {
            "status": "running",
            "timestamp": time.time(),
            "version": "1.0.0",
            "components": {
                "event_bus": _safe_import_status("core.events", "EventBus"),
                "knowledge_graph": _safe_import_status("core.knowledge_graph", "KnowledgeGraph"),
                "tracer": _safe_import_status("core.observability", "Tracer"),
                "metrics": _safe_import_status("core.observability", "MetricsCollector"),
            },
        }

    @app.get("/api/v1/metrics")
    async def get_metrics_endpoint() -> dict[str, Any]:
        """Get observability metrics."""
        try:
            from core.observability import get_metrics
            return get_metrics().get_all()
        except ImportError:
            return {"error": "Observability module not available"}

    @app.get("/api/v1/traces")
    async def get_traces(limit: int = 50) -> list[dict[str, Any]]:
        """Get recent trace spans."""
        try:
            from core.observability import get_tracer
            return get_tracer().get_traces(limit=min(limit, 500))
        except ImportError:
            return []

    @app.get("/api/v1/knowledge")
    async def get_knowledge_stats() -> dict[str, Any]:
        """Get knowledge graph statistics."""
        try:
            from core.knowledge_graph import get_knowledge_graph
            return get_knowledge_graph().stats()
        except ImportError:
            return {"error": "Knowledge graph not available"}

    @app.get("/api/v1/knowledge/entities")
    async def get_knowledge_entities(
        entity_type: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Get knowledge graph entities."""
        try:
            from core.knowledge_graph import get_knowledge_graph
            kg = get_knowledge_graph()
            entities = kg.find_entities(entity_type=entity_type, limit=limit)
            return [
                {
                    "id": e.entity_id,
                    "type": e.entity_type,
                    "properties": e.properties,
                    "session": e.session_id,
                }
                for e in entities
            ]
        except ImportError:
            return []


def _register_event_endpoints(app) -> None:
    """Register SSE event stream endpoint."""
    from fastapi.responses import StreamingResponse

    @app.get("/api/v1/events")
    async def event_stream():
        """Server-Sent Events stream of real-time DRAKBEN events."""
        async def generate():
            try:
                from core.events import get_event_bus

                bus = get_event_bus()
                queue: asyncio.Queue = asyncio.Queue(maxsize=1000)

                def handler(event) -> None:
                    try:
                        queue.put_nowait(event)
                    except asyncio.QueueFull:
                        pass  # Drop oldest-unread events under backpressure

                bus.subscribe_all(handler)

                try:
                    while True:
                        try:
                            event = await asyncio.wait_for(queue.get(), timeout=30.0)
                            data = json.dumps({
                                "type": event.type.value,
                                "data": event.data,
                                "timestamp": event.timestamp,
                                "source": event.source,
                            }, default=str)
                            yield f"data: {data}\n\n"
                        except TimeoutError:
                            # Send keepalive
                            yield f"data: {json.dumps({'type': 'keepalive', 'timestamp': time.time()})}\n\n"
                finally:
                    bus.unsubscribe_all(handler)

            except ImportError:
                yield f"data: {json.dumps({'error': 'EventBus not available'})}\n\n"

        return StreamingResponse(
            generate(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
            },
        )


def _register_agent_endpoints(app) -> None:
    """Register agent state and control endpoints."""

    @app.get("/api/v1/state")
    async def get_agent_state() -> dict[str, Any]:
        """Get current AgentState snapshot."""
        try:
            from core.agent.state import AgentState
            state = AgentState()
            return {
                "target": state.target,
                "phase": state.phase.value if state.phase else None,
                "iteration": state.iteration_count,
                "max_iterations": state.max_iterations,
                "services": {
                    str(port): {
                        "name": svc.name,
                        "version": svc.version,
                    }
                    for port, svc in state.open_services.items()
                },
                "vulnerabilities": len(state.vulnerabilities),
                "has_foothold": state.has_foothold,
                "foothold_method": state.foothold_method,
            }
        except Exception:
            logger.debug("Agent state retrieval failed", exc_info=True)
            return {"error": "Failed to retrieve agent state"}

    @app.get("/api/v1/plan")
    async def get_current_plan() -> dict[str, Any]:
        """Get current execution plan."""
        return {
            "info": "Plan data available via EventBus PLAN_* events",
            "note": "Connect to /api/v1/events for real-time updates",
        }

    @app.post("/api/v1/agent/stop")
    async def stop_agent() -> dict[str, str]:
        """Stop the running agent."""
        try:
            from core.stop_controller import stop
            stop()
            return {"status": "stop_requested"}
        except Exception:
            logger.debug("Agent stop failed", exc_info=True)
            return {"status": "error", "message": "Failed to stop agent"}


def _safe_import_status(module: str, cls: str) -> str:
    """Check if a module/class is available."""
    try:
        import importlib
        mod = importlib.import_module(module)
        getattr(mod, cls)
        return "available"
    except (ImportError, AttributeError):
        return "not_installed"


def run_web_ui(host: str = "0.0.0.0", port: int = 8484) -> None:  # noqa: S104
    """Start the web UI server."""
    try:
        import uvicorn
    except ImportError:
        logger.error(
            "uvicorn not installed. Install with: pip install uvicorn",
        )
        return

    app = create_app()
    if app is None:
        return

    uvicorn.run(app, host=host, port=port, log_level="info")
