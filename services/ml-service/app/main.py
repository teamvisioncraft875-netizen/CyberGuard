import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

from app.routers.analyze import router as analyze_router

load_dotenv()

app = FastAPI(
    title="CYBERGUARD AI/ML Microservice",
    description="Threat detection, anomaly scoring, and explanation generation engine",
    version="1.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Health & Readiness Probe
@app.get("/health", tags=["Health"])
@app.get("/internal/health", tags=["Health"])
@app.get("/health/readiness", tags=["Health"])
async def health_check():
    """Service liveness and readiness probe endpoint."""
    from app.services.system_engine import _MODEL_PATH, _ANOMALY_PATH

    url_engine_ready = True
    preprocessor_ready = True
    network_supervised_ready = _MODEL_PATH.exists()
    network_anomaly_ready = _ANOMALY_PATH.exists()
    all_ready = (
        url_engine_ready
        and preprocessor_ready
        and network_supervised_ready
        and network_anomaly_ready
    )

    return {
        "status": "ok" if all_ready else "degraded",
        "service": "cyberguard-ml-service",
        "version": "1.0.0",
        "readiness": {
            "url_engine_available": url_engine_ready,
            "network_supervised_available": network_supervised_ready,
            "network_anomaly_available": network_anomaly_ready,
            "checkpoints_readable": network_supervised_ready and network_anomaly_ready,
            "preprocessing_available": preprocessor_ready,
        },
    }

# Wire Analysis Routers (internal, API v1, and direct)
app.include_router(analyze_router, prefix="/internal")
app.include_router(analyze_router, prefix="/api/v1")
app.include_router(analyze_router)

if __name__ == "__main__":
    import uvicorn
    # Support ML_PORT explicitly to avoid colliding with Node.js backend gateway (PORT=5000).
    # If PORT is inherited from a shared root environment and equals 5000, default safely to 8000.
    ml_port_env = os.getenv("ML_PORT")
    if ml_port_env:
        port = int(ml_port_env)
    else:
        raw_port = int(os.getenv("PORT", 8000))
        port = 8000 if raw_port == 5000 else raw_port
    uvicorn.run("app.main:app", host="0.0.0.0", port=port, reload=True)
