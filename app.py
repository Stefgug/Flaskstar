import base64
import hashlib
import hmac
import json
import os
import threading
import time
from datetime import datetime, timezone
from ipaddress import ip_address

from flask import Flask, render_template, request, jsonify, Response, send_from_directory, abort, has_request_context
from werkzeug.middleware.proxy_fix import ProxyFix
import requests

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

RAGSTAR_API_URL = os.getenv("RAGSTAR_API_URL", "http://ragstar").rstrip("/")
ANALYTICS_LOG_PATH = os.getenv("ANALYTICS_LOG_PATH", os.path.join(app.instance_path, "analytics.jsonl"))
ANALYTICS_USER = os.getenv("ANALYTICS_USER", "admin")
ANALYTICS_PASS = os.getenv("ANALYTICS_PASS", "changeme")
ANALYTICS_SALT = os.getenv("ANALYTICS_SALT", "analytics-salt")
ANALYTICS_GEO = os.getenv("ANALYTICS_GEO", "1") == "1"
ANALYTICS_MAX_EVENTS = int(os.getenv("ANALYTICS_MAX_EVENTS", "200"))
ALLOWED_ADMIN_IPS = {
    ip.strip()
    for ip in os.getenv("ANALYTICS_ALLOWED_IPS", "90.92.127.233").split(",")
    if ip.strip()
}
_analytics_lock = threading.Lock()
_geo_cache = {}


@app.errorhandler(401)
def unauthorized(_error):
    response = jsonify({"error": "Unauthorized"})
    response.status_code = 401
    response.headers["WWW-Authenticate"] = 'Basic realm="Analytics"'
    return response


def _ensure_analytics_dir():
    os.makedirs(os.path.dirname(ANALYTICS_LOG_PATH), exist_ok=True)


def _hash_ip(value: str) -> str:
    digest = hashlib.sha256(f"{ANALYTICS_SALT}:{value}".encode("utf-8")).hexdigest()
    return digest[:16]


def _anonymize_ip(value: str) -> str:
    try:
        addr = ip_address(value)
    except ValueError:
        return "unknown"

    if addr.version == 4:
        parts = value.split(".")
        if len(parts) == 4:
            parts[-1] = "0"
            return ".".join(parts)
        return "unknown"

    if addr.version == 6:
        chunks = value.split(":")
        if len(chunks) >= 3:
            return ":".join(chunks[:3]) + "::"
        return "::"
    return "unknown"


def _get_client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _is_admin_ip_allowed(ip_value: str) -> bool:
    return ip_value in ALLOWED_ADMIN_IPS


def _is_private_ip(value: str) -> bool:
    try:
        return ip_address(value).is_private
    except ValueError:
        return True


def _lookup_geo(ip_value: str) -> dict:
    if not ANALYTICS_GEO or _is_private_ip(ip_value):
        return {}
    if ip_value in _geo_cache:
        return _geo_cache[ip_value]

    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip_value}",
            params={"fields": "status,country,regionName,city"},
            timeout=1.5,
        )
        data = response.json()
        if data.get("status") != "success":
            _geo_cache[ip_value] = {}
            return {}
        geo = {
            "country": data.get("country"),
            "region": data.get("regionName"),
            "city": data.get("city"),
        }
        _geo_cache[ip_value] = geo
        return geo
    except (requests.RequestException, ValueError):
        _geo_cache[ip_value] = {}
        return {}


def log_event(event: dict) -> None:
    _ensure_analytics_dir()
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **event,
    }
    if has_request_context():
        client_ip = _get_client_ip()
        payload.setdefault("ip_hash", _hash_ip(client_ip))
        payload.setdefault("ip_anon", _anonymize_ip(client_ip))
        if "country" not in payload and "region" not in payload:
            payload.update(_lookup_geo(client_ip))
    with _analytics_lock:
        with open(ANALYTICS_LOG_PATH, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload) + "\n")


def _parse_basic_auth():
    header = request.headers.get("Authorization", "")
    if not header.startswith("Basic "):
        return None, None
    try:
        encoded = header.split(" ", 1)[1]
        decoded = base64.b64decode(encoded).decode("utf-8")
        username, password = decoded.split(":", 1)
        return username, password
    except (ValueError, UnicodeDecodeError, base64.binascii.Error):
        return None, None


def _require_basic_auth():
    username, password = _parse_basic_auth()
    if not (username and password):
        return False
    return hmac.compare_digest(username, ANALYTICS_USER) and hmac.compare_digest(password, ANALYTICS_PASS)


@app.get("/health")
def health():
    return jsonify({"status": "ok"}), 200


@app.after_request
def add_security_headers(response):
    if request.is_secure or request.headers.get("X-Forwarded-Proto", "") == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"

    if request.method == "GET" and response.mimetype == "text/html":
        if not request.path.startswith("/static") and request.path not in {"/health", "/admin/analytics"}:
            client_ip = _get_client_ip()
            geo = _lookup_geo(client_ip)
            log_event({
                "event": "page_view",
                "path": request.path,
                "referrer": request.headers.get("Referer"),
                "user_agent": request.headers.get("User-Agent"),
                "ip_hash": _hash_ip(client_ip),
                "ip_anon": _anonymize_ip(client_ip),
                **geo,
            })
    return response

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/portfolio")
def portfolio():
    return render_template("portfolio.html")


@app.route("/resume")
def resume():
    return render_template("resume.html")


@app.route("/cv/<path:filename>")
def download_cv(filename):
    cv_dir = os.path.join(app.root_path, "CV")
    return send_from_directory(cv_dir, filename)


@app.route("/portfolio/RAGstar")
@app.route("/ragstar")
def ragstar():
    return render_template("ragstar.html")


@app.route("/admin/analytics")
def analytics_dashboard():
    client_ip = _get_client_ip()
    if not _is_admin_ip_allowed(client_ip):
        abort(403, description="Forbidden")
    if not _require_basic_auth():
        abort(401, description="Unauthorized")

    events = []
    if os.path.exists(ANALYTICS_LOG_PATH):
        with open(ANALYTICS_LOG_PATH, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    events = events[-ANALYTICS_MAX_EVENTS:]
    page_views = [item for item in events if item.get("event") == "page_view"]
    unique_visitors = len({item.get("ip_hash") for item in page_views if item.get("ip_hash")})

    page_counts = {}
    for item in page_views:
        path = item.get("path", "unknown")
        page_counts[path] = page_counts.get(path, 0) + 1

    top_pages = sorted(page_counts.items(), key=lambda kv: kv[1], reverse=True)[:10]

    rag_events = [item for item in events if item.get("event", "").startswith("ragstar_")]
    return render_template(
        "admin_analytics.html",
        events=list(reversed(events)),
        total_views=len(page_views),
        unique_visitors=unique_visitors,
        top_pages=top_pages,
        rag_events=list(reversed(rag_events)),
    )


@app.post("/ragstar/query")
def ragstar_query():
    payload = request.get_json(silent=True) or {}
    question = str(payload.get("question", "")).strip()
    num_results = payload.get("num_results", 5)

    if not question:
        return jsonify({"error": "Question is required."}), 400

    start_time = time.perf_counter()
    try:
        response = requests.post(
            f"{RAGSTAR_API_URL}/ask",
            json={"question": question, "num_results": num_results},
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()
        elapsed_ms = int((time.perf_counter() - start_time) * 1000)
        tokens = data.get("tokens") if isinstance(data, dict) else None
        log_event({
            "event": "ragstar_query",
            "question": question,
            "num_results": num_results,
            "elapsed_ms": elapsed_ms,
            "tokens": tokens,
        })
        return jsonify(data)
    except requests.RequestException as exc:
        log_event({
            "event": "ragstar_query_error",
            "question": question,
            "num_results": num_results,
            "error": str(exc),
        })
        return jsonify({"error": "RAGstar API unavailable.", "details": str(exc)}), 502


@app.post("/ragstar/build-starred")
def ragstar_build_starred():
    payload = request.get_json(silent=True) or {}
    username = str(payload.get("username", "")).strip()

    if not username:
        return jsonify({"error": "GitHub username is required."}), 400

    try:
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "RAGstar-Portfolio",
        }

        gh_url = f"https://api.github.com/users/{username}/starred"
        gh_response = requests.get(
            gh_url,
            params={"per_page": 100},
            headers=headers,
            timeout=15,
        )
        gh_response.raise_for_status()
        starred = gh_response.json()
        repo_urls = [item.get("html_url") for item in starred if item.get("html_url")]

        if not repo_urls:
            return jsonify({"error": "No starred repositories found."}), 404

        build_response = requests.post(
            f"{RAGSTAR_API_URL}/build",
            json={"repositories": repo_urls},
            timeout=30,
        )
        build_response.raise_for_status()
        log_event({
            "event": "ragstar_build_starred",
            "username": username,
            "repo_count": len(repo_urls),
        })
        return jsonify({
            "status": "submitted",
            "count": len(repo_urls),
            "username": username,
            "ragstar": build_response.json(),
        })
    except requests.RequestException as exc:
        log_event({
            "event": "ragstar_build_starred_error",
            "username": username,
            "error": str(exc),
        })
        return jsonify({"error": "Failed to import starred repositories.", "details": str(exc)}), 502


@app.post("/ragstar/build-stream")
def ragstar_build_stream():
    """Proxy SSE stream from RAGstar /build/stream endpoint."""
    payload = request.get_json(silent=True) or {}
    repositories = payload.get("repositories", [])

    if not repositories:
        return jsonify({"error": "repositories list is required."}), 400

    log_event({
        "event": "ragstar_build_stream",
        "repo_count": len(repositories),
        "repositories": repositories,
    })

    def generate():
        try:
            with requests.post(
                f"{RAGSTAR_API_URL}/build/stream",
                json={"repositories": repositories},
                stream=True,
                timeout=600,
            ) as response:
                response.raise_for_status()
                for line in response.iter_lines():
                    if line:
                        yield line.decode("utf-8") + "\n"
            # Add this to see if stream completed normally
            app.logger.info("SSE stream completed normally")
        except requests.RequestException as exc:
            app.logger.error(f"SSE stream error: {exc}")
            yield f"data: {{\"event\": \"error\", \"message\": \"{str(exc)}\"}}\n\n"

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
