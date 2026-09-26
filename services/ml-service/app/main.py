import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

from app.routers.analyze_router import router as analyze_router

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

# Health Check Probe
@app.get("/health", tags=["Health"])
@app.get("/internal/health", tags=["Health"])
async def health_check():
    """Service liveness and readiness probe endpoint."""
    return {
        "status": "ok",
        "service": "cyberguard-ml-service",
        "version": "1.0.0"
    }

# Wire Internal Analysis Router
app.include_router(analyze_router, prefix="/internal")

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("app.main:app", host="0.0.0.0", port=port, reload=True)
