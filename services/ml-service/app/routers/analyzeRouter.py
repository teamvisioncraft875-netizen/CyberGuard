from fastapi import APIRouter, status
# pyrefly: ignore [missing-import]
from app.schemas.analyze import (
    MessageAnalyzeRequest,
    UrlAnalyzeRequest,
    MediaAnalyzeRequest,
    MediaType,
    LoginAnalyzeRequest,
    SystemAnalyzeRequest,
    MalwareAnalyzeRequest,
    UnifiedAnalysisResponse
)
from app.services.message_engine import analyze_message
from app.services.url_engine import analyze_url
from app.services.media_engine import analyze_media
from app.services.login_engine import analyze_login
from app.services.system_engine import analyze_system
from app.services.malware_engine import analyze_malware, analyze_malware_bytes

router = APIRouter(prefix="/analyze", tags=["Threat Analysis Engines"])


@router.post("/message", response_model=UnifiedAnalysisResponse, status_code=status.HTTP_200_OK)
async def analyze_message_endpoint(payload: MessageAnalyzeRequest) -> UnifiedAnalysisResponse:
    """Analyze message text for phishing, social engineering, and urgent credential lures."""
    return analyze_message(payload)


@router.post("/url", response_model=UnifiedAnalysisResponse, status_code=status.HTTP_200_OK)
async def analyze_url_endpoint(payload: UrlAnalyzeRequest) -> UnifiedAnalysisResponse:
    """Analyze domain URL for typosquatting, look-alike patterns, and reputation anomalies."""
    return analyze_url(payload)


import base64
from typing import Tuple, Optional
from fastapi import Request, HTTPException

def _inspect_media_magic_bytes(data: bytes) -> Tuple[Optional[MediaType], str]:
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WAVE":
        return MediaType.AUDIO, "audio/wav"
    if len(data) >= 4 and data[:4] == b"fLaC":
        return MediaType.AUDIO, "audio/flac"
    if len(data) >= 4 and (data[:3] == b"ID3" or data[:2] in (b"\xff\xfb", b"\xff\xf3", b"\xff\xf2")):
        return MediaType.AUDIO, "audio/mpeg"
    if len(data) >= 4 and data[:4] == b"OggS":
        return MediaType.AUDIO, "audio/ogg"
    if len(data) >= 8 and data[:8] == b"\x89PNG\r\n\x1a\n":
        return MediaType.IMAGE, "image/png"
    if len(data) >= 3 and data[:3] == b"\xff\xd8\xff":
        return MediaType.IMAGE, "image/jpeg"
    if len(data) >= 6 and (data[:6] in (b"GIF87a", b"GIF89a")):
        return MediaType.IMAGE, "image/gif"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return MediaType.IMAGE, "image/webp"
    return None, "application/octet-stream"


@router.post("/media", response_model=UnifiedAnalysisResponse, status_code=status.HTTP_200_OK)
async def analyze_media_endpoint(request: Request) -> UnifiedAnalysisResponse:
    """Analyze uploaded images or audio recordings for synthetic manipulation or voice cloning."""
    content_type = request.headers.get("content-type", "")

    if "multipart/form-data" in content_type:
        form = await request.form()
        uploaded_file = form.get("file")
        if not uploaded_file:
            raise HTTPException(status_code=400, detail="Missing required 'file' in multipart form data")

        file_bytes = await uploaded_file.read()
        if len(file_bytes) > 10 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="File size exceeds maximum allowed 10 MB limit")

        if len(file_bytes) < 32:
            raise HTTPException(status_code=400, detail="File payload is empty or too short for forensic evaluation")

        detected_media_type, mime = _inspect_media_magic_bytes(file_bytes)
        if not detected_media_type:
            raise HTTPException(status_code=415, detail="Unsupported media format. Supported formats: WAV, FLAC, MP3, OGG, PNG, JPEG, GIF, WEBP")

        media_type_form = form.get("media_type")
        if media_type_form and media_type_form in ("audio", "image"):
            final_type = MediaType(media_type_form)
        else:
            final_type = detected_media_type

        data_uri = f"data:{mime};base64,{base64.b64encode(file_bytes).decode('ascii')}"
        req = MediaAnalyzeRequest(file_url=data_uri, media_type=final_type)
        return analyze_media(req)

    else:
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")
        try:
            payload = MediaAnalyzeRequest(**body)
        except Exception as e:
            raise HTTPException(status_code=422, detail=str(e))

        try:
            return analyze_media(payload)
        except ValueError as e:
            err_msg = str(e)
            if "exceeds" in err_msg.lower() and "limit" in err_msg.lower():
                raise HTTPException(status_code=413, detail=err_msg)
            if "ssrf" in err_msg.lower() or "prohibited" in err_msg.lower():
                raise HTTPException(status_code=403, detail=err_msg)
            if "unsupported" in err_msg.lower() or "format" in err_msg.lower():
                raise HTTPException(status_code=415, detail=err_msg)
            raise HTTPException(status_code=400, detail=err_msg)
        except FileNotFoundError as e:
            raise HTTPException(status_code=404, detail=str(e))


@router.post("/login", response_model=UnifiedAnalysisResponse, status_code=status.HTTP_200_OK)
async def analyze_login_endpoint(payload: LoginAnalyzeRequest) -> UnifiedAnalysisResponse:
    """Analyze login metadata for credential stuffing, geographical velocity, and device anomalies."""
    return analyze_login(payload)


@router.post("/system", response_model=UnifiedAnalysisResponse, status_code=status.HTTP_200_OK)
async def analyze_system_endpoint(payload: SystemAnalyzeRequest) -> UnifiedAnalysisResponse:
    """Analyze workstation telemetry for process anomalies, network surges, and host deviations."""
    return analyze_system(payload)


@router.post("/malware", response_model=UnifiedAnalysisResponse, status_code=status.HTTP_200_OK)
async def analyze_malware_endpoint(request: Request) -> UnifiedAnalysisResponse:
    """Analyze Windows PE binary executable statically for malware and ransomware indicators."""
    content_type = request.headers.get("content-type", "")

    if "multipart/form-data" in content_type:
        form = await request.form()
        uploaded_file = form.get("file")
        if not uploaded_file:
            raise HTTPException(status_code=400, detail="Missing required 'file' in multipart form data")

        file_bytes = await uploaded_file.read()
        if len(file_bytes) > 50 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="File size exceeds maximum allowed 50 MB limit for static analysis")

        filename = getattr(uploaded_file, "filename", "uploaded_sample.bin")
        return analyze_malware_bytes(file_bytes, filename=filename)

    else:
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")
        try:
            payload = MalwareAnalyzeRequest(**body)
        except Exception as e:
            raise HTTPException(status_code=422, detail=str(e))

        try:
            return analyze_malware(payload)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

