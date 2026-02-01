import os

from flask import Flask, render_template, request, jsonify, Response
from werkzeug.middleware.proxy_fix import ProxyFix
import requests

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

RAGSTAR_API_URL = os.getenv("RAGSTAR_API_URL", "http://ragstar").rstrip("/")


@app.get("/health")
def health():
    return jsonify({"status": "ok"}), 200


@app.after_request
def add_security_headers(response):
    if request.is_secure or request.headers.get("X-Forwarded-Proto", "") == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    return response

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/portfolio")
def portfolio():
    return render_template("portfolio.html")


@app.route("/portfolio/RAGstar")
@app.route("/ragstar")
def ragstar():
    return render_template("ragstar.html")


@app.post("/ragstar/query")
def ragstar_query():
    payload = request.get_json(silent=True) or {}
    question = str(payload.get("question", "")).strip()
    num_results = payload.get("num_results", 5)

    if not question:
        return jsonify({"error": "Question is required."}), 400

    try:
        response = requests.post(
            f"{RAGSTAR_API_URL}/ask",
            json={"question": question, "num_results": num_results},
            timeout=30,
        )
        response.raise_for_status()
        return jsonify(response.json())
    except requests.RequestException as exc:
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
        return jsonify({
            "status": "submitted",
            "count": len(repo_urls),
            "username": username,
            "ragstar": build_response.json(),
        })
    except requests.RequestException as exc:
        return jsonify({"error": "Failed to import starred repositories.", "details": str(exc)}), 502


@app.post("/ragstar/build-stream")
def ragstar_build_stream():
    """Proxy SSE stream from RAGstar /build/stream endpoint."""
    payload = request.get_json(silent=True) or {}
    repositories = payload.get("repositories", [])

    if not repositories:
        return jsonify({"error": "repositories list is required."}), 400

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
