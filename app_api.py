import os
import time
import threading
from collections import defaultdict, deque
from typing import Any

import storage
from detector_core import ScamDetector, get_risk_level, get_advice

try:
    from fastapi import Depends, FastAPI, Header, HTTPException, Request
    from fastapi.responses import JSONResponse
    FASTAPI_AVAILABLE = True
except ImportError:
    FastAPI = None  # type: ignore[assignment]
    Depends = None  # type: ignore[assignment]
    Header = None  # type: ignore[assignment]
    HTTPException = RuntimeError  # type: ignore[assignment]
    Request = None  # type: ignore[assignment]
    JSONResponse = None  # type: ignore[assignment]
    FASTAPI_AVAILABLE = False


VALID_FEEDBACK_LABELS = {
    "true_positive",
    "false_positive",
    "false_negative",
    "true_negative",
    "correct",
}


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

    app = FastAPI(title="Zambian Scam Detector API", version="1.0.0")
    detector = ScamDetector()
    limiter = InMemoryRateLimiter()

    @app.on_event("startup")
    def _startup() -> None:
        if log_to_db:
            try:
                storage.init_database()
            except Exception as e:
                print(f"[WARN] Could not initialize database: {e}")

    async def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
        if x_api_key != api_key:
            raise HTTPException(status_code=401, detail="Unauthorized")

    def _client_key(request: Request) -> str:
        client_host = request.client.host if request.client else "unknown"
        return f"{client_host}:{request.url.path}"

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

    @app.get("/health")
    async def health_check(request: Request):
        _check_default_limits(request)
        return {"status": "healthy", "service": "Zambian Scam Detector API"}

    @app.post("/analyze", dependencies=[Depends(require_api_key)])
    async def analyze_message(request: Request):
        _check_default_limits(request)
        limiter.check(_client_key(request), "analyze", analyze_limit)

        data: dict[str, Any] = await request.json()
        message = data.get("message")
        provider = data.get("provider")

        if not isinstance(message, str) or not message.strip():
            raise HTTPException(status_code=400, detail="Missing or empty 'message' field in request body")

        score, flags = detector.analyze(message)
        risk_level, _ = get_risk_level(score)
        advice = get_advice(score, flags)

        det_id = _log_detection_if_enabled(
            message=message,
            score=score,
            flags=flags,
            risk_level=risk_level,
            source="api_v1",
            provider=provider,
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

    @app.post("/analyze/batch", dependencies=[Depends(require_api_key)])
    async def analyze_batch(request: Request):
        _check_default_limits(request)
        limiter.check(_client_key(request), "batch", batch_limit)

        data: dict[str, Any] = await request.json()
        messages = data.get("messages")
        provider = data.get("provider")
        source = data.get("source", "provider_api_v1")

        if not isinstance(messages, list) or not messages:
            raise HTTPException(status_code=400, detail="Missing or empty 'messages' list in request body")
        if len(messages) > batch_max_items:
            raise HTTPException(status_code=400, detail=f"Batch too large. Max items: {batch_max_items}")

        results = []
        for i, message in enumerate(messages):
            if not isinstance(message, str) or not message.strip():
                raise HTTPException(status_code=400, detail=f"messages[{i}] must be a non-empty string")

            score, flags = detector.analyze(message)
            risk_level, _ = get_risk_level(score)
            advice = get_advice(score, flags)
            det_id = _log_detection_if_enabled(
                message=message,
                score=score,
                flags=flags,
                risk_level=risk_level,
                source=source,
                provider=provider,
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

    @app.post("/feedback", dependencies=[Depends(require_api_key)])
    async def submit_feedback(request: Request):
        _check_default_limits(request)
        limiter.check(_client_key(request), "feedback", feedback_limit)

        data: dict[str, Any] = await request.json()
        detection_id = data.get("detection_id")
        source = data.get("source", "api_v1")
        label = data.get("label")
        note = data.get("note", "")

        if not isinstance(detection_id, int) or detection_id <= 0:
            raise HTTPException(status_code=400, detail="'detection_id' must be a positive integer")
        if label not in VALID_FEEDBACK_LABELS:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid label. Allowed: {sorted(VALID_FEEDBACK_LABELS)}",
            )

        try:
            storage.record_feedback(
                detection_id=detection_id,
                source=source,
                label=label,
                note=note,
            )
        except Exception as e:
            print(f"[WARN] Failed to record feedback: {e}")
            raise HTTPException(status_code=500, detail="Failed to record feedback") from e

        return {"success": True, "recorded": True}

    @app.get("/detections/{detection_id}", dependencies=[Depends(require_api_key)])
    async def get_detection(detection_id: int, request: Request):
        _check_default_limits(request)
        record = storage.get_detection_by_id(detection_id)
        if not record:
            raise HTTPException(status_code=404, detail="Detection not found")
        return {"success": True, "detection": record}

    @app.get("/dashboard/summary", dependencies=[Depends(require_api_key)])
    async def dashboard_summary(request: Request, date: str | None = None, provider: str | None = None):
        _check_default_limits(request)
        summary = storage.ProviderDashboard.get_daily_summary(date_str=date, provider=provider)
        return {"success": True, "summary": summary}

    @app.get("/dashboard/accuracy", dependencies=[Depends(require_api_key)])
    async def dashboard_accuracy(request: Request, provider: str | None = None):
        _check_default_limits(request)
        stats = storage.ProviderDashboard.get_feedback_accuracy(provider=provider)
        return {"success": True, "accuracy": stats}

    @app.post("/dashboard/export", dependencies=[Depends(require_api_key)])
    async def dashboard_export(request: Request):
        _check_default_limits(request)
        limiter.check(_client_key(request), "export", export_limit)

        data: dict[str, Any] = await request.json()
        provider = data.get("provider")
        min_risk_level = data.get("min_risk_level", "MODERATE RISK")

        try:
            output_file = storage.ProviderDashboard.export_csv_for_review(
                min_risk_level=min_risk_level,
                provider=provider,
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
