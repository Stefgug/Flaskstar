import os

from flask import Flask, render_template, request, jsonify, Response
import requests

app = Flask(__name__)

RAGSTAR_API_URL = os.getenv("RAGSTAR_API_URL", "http://localhost:8001")

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
    query = str(payload.get("query", "")).strip()
    num_results = payload.get("num_results", 5)

    if not query:
        return jsonify({"error": "Query is required."}), 400

    try:
        response = requests.post(
            f"{RAGSTAR_API_URL}/query",
            json={"query": query, "num_results": num_results},
            timeout=20,
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
                timeout=300,
            ) as response:
                response.raise_for_status()
                for line in response.iter_lines():
                    if line:
                        yield line.decode("utf-8") + "\n"
        except requests.RequestException as exc:
            yield f"data: {{\"event\": \"error\", \"message\": \"{str(exc)}\"}}\n\n"

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
