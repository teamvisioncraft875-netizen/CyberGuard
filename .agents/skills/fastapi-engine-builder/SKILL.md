---
name: fastapi-engine-builder
description: Builds AI/ML detection engines, Pydantic schemas, asynchronous inference pipelines, and explanation generation in FastAPI for CYBERGUARD. Activate when creating or modifying services/ml-service, implementing threat detection algorithms, wrapping open-source models (ViT, ASVspoof, Isolation Forest, LLM), or optimizing inference performance.
---

# FastAPI Engine Builder — Threat Detection & Machine Learning

This skill guides the construction, optimization, and integration of the AI/ML detection engines inside the **Python / FastAPI ML Service** (`services/ml-service/`).

> **Authoritative Context:** See [.agents/PROJECT_CONTEXT.md](file:///c:/Users/subha/Downloads/CyberGuard/.agents/PROJECT_CONTEXT.md) and [.agents/rules/cyberguard.md](file:///c:/Users/subha/Downloads/CyberGuard/.agents/rules/cyberguard.md).

---

## 1. Directory Structure & Layer Responsibilities
All code in `services/ml-service/` must maintain strict separation of concerns:

```
services/ml-service/
├── main.py              # FastAPI app setup, CORS, and router registration only
├── routers/             # Endpoint definitions and request/response annotations ONLY
├── services/            # Engine orchestration, model pipelines, inference logic
├── schemas/             # Pydantic input and output validation models
├── engines/             # Domain-specific detection logic
│   ├── phishing/        # LLM zero-shot + TF-IDF/XGBoost classifier
│   ├── multimedia/      # Pretrained ViT (image) & ASVspoof (audio) detectors
│   ├── impersonation/   # Brand heuristics, look-alike domain, SPF/DKIM rules
│   └── anomaly/         # Isolation Forest for login/telemetry spikes
└── utils/               # Preprocessing, tokenization, text cleaning, model loaders
```

---

## 2. Standard Engine Schema Definition (`schemas/detection.py`)

```python
from pydantic import BaseModel, Field
from typing import Literal, Dict, Any, Optional

RiskTier = Literal["Safe", "Low", "Medium", "High", "Critical"]

class ScanRequest(BaseModel):
    content_type: Literal["text", "url", "image", "audio", "telemetry"]
    payload: str  # text content, url string, base64 data, or JSON string
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)

class ThreatResponse(BaseModel):
    risk_level: RiskTier
    risk_score: int = Field(..., ge=0, le=100)
    explanation: str
    recommended_action: str
    mitre_technique: Optional[str] = None
    signals: Dict[str, Any] = Field(default_factory=dict)
```

---

## 3. Router Pattern (`routers/phishing.py`)
```python
from fastapi import APIRouter, Depends, HTTPException
from schemas.detection import ScanRequest, ThreatResponse
from services.phishing_service import PhishingService, get_phishing_service

router = APIRouter(prefix="/detect/phishing", tags=["Phishing Engine"])

# Router only handles routing & Pydantic mapping — NO heavy inference logic here!
@router.post("", response_model=ThreatResponse)
async def detect_phishing(
    request: ScanRequest,
    service: PhishingService = Depends(get_phishing_service)
):
    try:
        result = await service.analyze(request.payload, request.metadata)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Phishing analysis failed: {str(e)}")
```

---

## 4. Open-Source Model Strategy & Pragmatic Constraints
1. **Phishing Text:** Prompt-engineered LLM with few-shot examples for novel scams. Use local TF-IDF + Logistic Regression/XGBoost as an offline/fast-path fallback.
2. **Deepfake Image:** Load pretrained Vision Transformer (`google/vit-base-patch16-224` fine-tuned for deepfake classification) using Hugging Face `pipeline`.
3. **Deepfake Audio:** Pretrained voice anti-spoofing weights trained on ASVspoof.
4. **Telemetry Anomaly:** `IsolationForest` from `scikit-learn` loaded once at startup.
5. **No Long Blocking Calls:** Use `asyncio.to_thread` for blocking CPU-bound model inference to prevent stalling the FastAPI event loop.

---

## 5. Engine Implementation Checklist
- [ ] No inference or model loading directly inside `routers/`.
- [ ] Model checkpoints loaded once at startup as singletons (not on every request).
- [ ] Output strictly conforms to `ThreatResponse` schema (`risk_level`, `risk_score`, `explanation`, `recommended_action`).
- [ ] Execution latency stays within target boundaries (< 500ms for text/URL, < 2s for media).
- [ ] Plain-English explanation clearly describes *what* triggered the verdict.
