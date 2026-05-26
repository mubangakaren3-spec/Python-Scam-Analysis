import os
import time
import threading
import storage
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from typing import Any, Literal

import storage
from detector_core import ScamDetector, get_risk_level, get_advice

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

try:
    from fastapi import Depends, FastAPI, Header, HTTPException, Request
    from fastapi.responses import JSONResponse, HTMLResponse, FileResponse
    from fastapi.staticfiles import StaticFiles
    from fastapi.exceptions import RequestValidationError
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.middleware.trustedhost import TrustedHostMiddleware
    from pydantic import BaseModel, Field
    FASTAPI_AVAILABLE = True
except ImportError:
    FastAPI = None  # type: ignore[assignment]
    Depends = None  # type: ignore[assignment]
    Header = None  # type: ignore[assignment]
    HTTPException = RuntimeError  # type: ignore[assignment]
    Request = None  # type: ignore[assignment]
    JSONResponse = None  # type: ignore[assignment]
    RequestValidationError = Exception  # type: ignore[assignment]
    CORSMiddleware = None  # type: ignore[assignment]
    TrustedHostMiddleware = None  # type: ignore[assignment]
    BaseModel = object  # type: ignore[assignment]
    Field = lambda *args, **kwargs: None  # type: ignore[assignment]
    FASTAPI_AVAILABLE = False


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _parse_limit(limit_str: str) -> tuple[int, int]:
    parts = limit_str.strip().lower().split()
    if len(parts) != 3 or parts[1] != "per":
        raise ValueError(f"Invalid rate limit format: {limit_str}")

    count = int(parts[0])
    unit = parts[2]
    unit_to_seconds = {
        "second": 1,
        "seconds": 1,
        "minute": 60,
        "minutes": 60,
        "hour": 3600,
        "hours": 3600,
        "day": 86400,
        "days": 86400,
    }
    if unit not in unit_to_seconds:
        raise ValueError(f"Unsupported rate limit unit: {unit}")
    return count, unit_to_seconds[unit]


class InMemoryRateLimiter:
    def __init__(self):
        self._buckets: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str, limit_name: str, limit_spec: str) -> None:
        max_calls, window_seconds = _parse_limit(limit_spec)
        now = time.time()

        bucket_key = (key, limit_name)
        with self._lock:
            bucket = self._buckets[bucket_key]
            cutoff = now - window_seconds
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()

            if len(bucket) >= max_calls:
                raise HTTPException(status_code=429, detail="Rate limit exceeded")

            bucket.append(now)


def create_app():
    if not FASTAPI_AVAILABLE:
        raise RuntimeError(
            "FastAPI is not installed. Install dependencies with: "
            "pip install fastapi uvicorn"
        )

    api_key = os.getenv("SCAM_API_KEY", "zambia-scam-detector-v1")
    log_to_db = _env_bool("SCAM_API_LOG_TO_DB", True)
    limit_day = os.getenv("SCAM_API_LIMIT_DAY", "200 per day")
    limit_hour = os.getenv("SCAM_API_LIMIT_HOUR", "50 per hour")
    analyze_limit = os.getenv("SCAM_API_ANALYZE_LIMIT", "5 per minute")
    batch_limit = os.getenv("SCAM_API_BATCH_LIMIT", "2 per minute")
    feedback_limit = os.getenv("SCAM_API_FEEDBACK_LIMIT", "30 per minute")
    export_limit = os.getenv("SCAM_API_EXPORT_LIMIT", "10 per hour")
    batch_max_items = int(os.getenv("SCAM_API_BATCH_MAX_ITEMS", "100"))

    # Request Models
    class AnalyzeRequest(BaseModel):
        message: str = Field(..., min_length=1, description="Raw message text to analyze")
        provider: str | None = Field(None, description="Optional provider identifier")

    class AnalyzeBatchRequest(BaseModel):
        messages: list[str] = Field(..., min_length=1, max_length=batch_max_items, description="List of messages to analyze")
        provider: str | None = Field(None, description="Optional provider identifier")
        source: str = Field("provider_api_v1", description="Source identifier for logging")

    class FeedbackRequest(BaseModel):
        detection_id: int = Field(..., gt=0, description="ID of the detection being rated")
        label: str = Field(..., description="User feedback label")
        source: str = Field("api_v1", description="Feedback source identifier")
        note: str = Field("", description="Optional descriptive note")
        
    class DashboardExportRequest(BaseModel):
        provider: str | None = Field(None, description="Optional provider identifier")
        min_risk_level: str = Field("MODERATE RISK", description="Minimum risk level to export")

    # Response Models
    class AnalysisResult(BaseModel):
        score: int
        risk_level: str
        flags: list[str]
        advice: list[str]

    class AnalyzeResponse(BaseModel):
        success: bool
        detection_id: int | None
        analysis: AnalysisResult

    class BatchResultItem(BaseModel):
        index: int
        detection_id: int | None
        analysis: AnalysisResult

    class AnalyzeBatchResponse(BaseModel):
        success: bool
        count: int
        results: list[BatchResultItem]

    class FeedbackResponse(BaseModel):
        success: bool
        recorded: bool

    class HealthResponse(BaseModel):
        status: str
        service: str
        
    class DetectionResponse(BaseModel):
        success: bool
        detection: dict

    class DashboardSummaryResponse(BaseModel):
        success: bool
        summary: dict

    class DashboardAccuracyResponse(BaseModel):
        success: bool
        accuracy: dict

    class DashboardExportResponse(BaseModel):
        success: bool
        export_file: str

    # Initialize detector instance locally to avoid Uvicorn state context failures
    detector = ScamDetector()

    @asynccontextmanager
    async def lifespan(app_instance: FastAPI):
        if log_to_db:
            try:
                storage.init_database()
            except Exception as e:
                print(f"[WARN] Could not initialize database: {e}")
        yield

    app = FastAPI(
        title="Zambian Scam Detector API",
        version="1.0.0",
        lifespan=lifespan
    )
    
    if CORSMiddleware is not None:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    if TrustedHostMiddleware is not None:
        allowed_hosts = [h.strip() for h in os.getenv("ALLOWED_HOSTS", "*").split(",") if h.strip()]
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=allowed_hosts,
        )

    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    limiter = InMemoryRateLimiter()

    # Serve static files for the web interface
    if StaticFiles is not None:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        static_dir = os.path.join(base_dir, "static")
        if not os.path.exists(static_dir):
            os.makedirs(static_dir)
        app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/", response_class=HTMLResponse)
    async def get_index(request: Request):
        _check_default_limits(request)
        base_dir = os.path.dirname(os.path.abspath(__file__))
        index_path = os.path.join(base_dir, "static", "index.html")
        if not os.path.exists(index_path):
            raise HTTPException(status_code=404, detail="Web interface not found")
        
        try:
            with open(index_path, "r", encoding="utf-8") as f:
                content = f.read()
            
            # Inject the actual API key from the environment into the frontend
            # This ensures the Web UI always uses the correct key even if the user changes it
            content = content.replace(
                'const API_KEY = "zambia-scam-detector-v1";', 
                f'const API_KEY = "{api_key}";'
            )
            return HTMLResponse(content)
        except Exception as e:
            print(f"[ERROR] Failed to serve index.html: {e}")
            raise HTTPException(status_code=500, detail="Internal Server Error serving UI")

    async def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
        if x_api_key != api_key:
            raise HTTPException(status_code=401, detail="Unauthorized")

    def _client_key(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    def _check_default_limits(request: Request) -> None:
        key = _client_key(request)
        limiter.check(key, "default_day", limit_day)
        limiter.check(key, "default_hour", limit_hour)

    def _log_detection_if_enabled(message, score, flags, risk_level, source, provider):
        if not log_to_db:
            return None
        try:
            return storage.log_detection(
                message=message,
                score=score,
                flags=flags,
                risk_level=risk_level,
                source=source,
                provider=provider,
            )
        except Exception as e:
            print(f"[WARN] Failed to log detection: {e}")
            return None

    @app.exception_handler(HTTPException)
    async def http_exception_handler(_: Request, exc: HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"success": False, "error": exc.detail},
        )
        
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(_: Request, exc: RequestValidationError):
        return JSONResponse(
            status_code=422,
            content={"success": False, "error": str(exc)},
        )

    @app.get("/health", response_model=HealthResponse)
    async def health_check(request: Request):
        _check_default_limits(request)
        return {"status": "healthy", "service": "Zambian Scam Detector API"}

    @app.post("/analyze", dependencies=[Depends(require_api_key)], response_model=AnalyzeResponse)
    async def analyze_message(request: Request, body: AnalyzeRequest):
        _check_default_limits(request)
        limiter.check(_client_key(request), "analyze", analyze_limit)

        score, flags = detector.analyze(body.message)
        risk_level, _ = get_risk_level(score)
        advice = get_advice(score, flags)

        det_id = _log_detection_if_enabled(
            message=body.message,
            score=score,
            flags=flags,
            risk_level=risk_level,
            source="api_v1",
            provider=body.provider,
        )

        return {
            "success": True,
            "detection_id": det_id,
            "analysis": {
                "score": score,
                "risk_level": risk_level,
                "flags": flags,
                "advice": advice,
            },
        }

    @app.post("/analyze/batch", dependencies=[Depends(require_api_key)], response_model=AnalyzeBatchResponse)
    async def analyze_batch(request: Request, body: AnalyzeBatchRequest):
        _check_default_limits(request)
        limiter.check(_client_key(request), "batch", batch_limit)

        # Validate all messages upfront
        for i, message in enumerate(body.messages):
            if not message.strip():
                raise HTTPException(status_code=400, detail=f"messages[{i}] consists only of whitespace")

        results = []
        for i, message in enumerate(body.messages):
            score, flags = detector.analyze(message)
            risk_level, _ = get_risk_level(score)
            advice = get_advice(score, flags)
            det_id = _log_detection_if_enabled(
                message=message,
                score=score,
                flags=flags,
                risk_level=risk_level,
                source=body.source,
                provider=body.provider,
            )
            results.append({
                "index": i,
                "detection_id": det_id,
                "analysis": {
                    "score": score,
                    "risk_level": risk_level,
                    "flags": flags,
                    "advice": advice,
                },
            })

        return {
            "success": True,
            "count": len(results),
            "results": results,
        }

    @app.post("/feedback", dependencies=[Depends(require_api_key)], response_model=FeedbackResponse)
    async def submit_feedback(request: Request, body: FeedbackRequest):
        _check_default_limits(request)
        limiter.check(_client_key(request), "feedback", feedback_limit)

        # Validate label explicitly so we can return a 400 on bad input
        allowed_labels = {"true_positive", "false_positive", "false_negative", "true_negative", "correct"}
        if body.label not in allowed_labels:
            raise HTTPException(status_code=400, detail="Invalid feedback label")

        try:
            storage.record_feedback(
                detection_id=body.detection_id,
                source=body.source,
                label=body.label,
                note=body.note,
            )
        except Exception as e:
            print(f"[WARN] Failed to record feedback: {e}")
            raise HTTPException(status_code=500, detail="Failed to record feedback") from e

        return {"success": True, "recorded": True}

    @app.get("/detections/{detection_id}", dependencies=[Depends(require_api_key)], response_model=DetectionResponse)
    async def get_detection(detection_id: int, request: Request):
        _check_default_limits(request)
        record = storage.get_detection_by_id(detection_id)
        if not record:
            raise HTTPException(status_code=404, detail="Detection not found")
        return {"success": True, "detection": record}

    @app.get("/dashboard/summary", dependencies=[Depends(require_api_key)], response_model=DashboardSummaryResponse)
    async def dashboard_summary(request: Request, date: str | None = None, provider: str | None = None):
        _check_default_limits(request)
        summary = storage.ProviderDashboard.get_daily_summary(date_str=date, provider=provider)
        return {"success": True, "summary": summary}

    @app.get("/dashboard/accuracy", dependencies=[Depends(require_api_key)], response_model=DashboardAccuracyResponse)
    async def dashboard_accuracy(request: Request, provider: str | None = None):
        _check_default_limits(request)
        stats = storage.ProviderDashboard.get_feedback_accuracy(provider=provider)
        return {"success": True, "accuracy": stats}

    @app.post("/dashboard/export", dependencies=[Depends(require_api_key)], response_model=DashboardExportResponse)
    async def dashboard_export(request: Request, body: DashboardExportRequest):
        _check_default_limits(request)
        limiter.check(_client_key(request), "export", export_limit)

        try:
            output_file = storage.ProviderDashboard.export_csv_for_review(
                min_risk_level=body.min_risk_level,
                provider=body.provider,
            )
        except Exception as e:
            print(f"[WARN] Failed to export CSV: {e}")
            raise HTTPException(status_code=500, detail="Failed to export CSV") from e

        return {"success": True, "export_file": output_file}

    return app


if FASTAPI_AVAILABLE:
    app = create_app()
else:
    app = None


if __name__ == "__main__":
    if not FASTAPI_AVAILABLE:
        raise SystemExit("FastAPI not installed. Run: pip install fastapi uvicorn")
    import uvicorn

    uvicorn.run("app_api:app", host="0.0.0.0", port=5000, reload=False)
