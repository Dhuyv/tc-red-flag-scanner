"""
T&C Red Flag Scanner - Flask Server
Team: CorruptX
Cybersecurity Hackathon Platform
"""

import os
import sys
import json
from flask import Flask, request, jsonify, send_from_directory, render_template_string
from flask_cors import CORS
from bs4 import BeautifulSoup

from analyzer import ClauseAnalyzer

# Setup Flask application
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "frontend"))

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
CORS(app) # Allow cross-origin requests for local dev / dual-mode hosting

# Initialize Analyzer engine
analyzer = ClauseAnalyzer(os.path.join(BASE_DIR, "risk_rules.json"))

# Load Sample Policies
SAMPLE_POLICIES_PATH = os.path.join(BASE_DIR, "sample_policies.json")
try:
    with open(SAMPLE_POLICIES_PATH, "r", encoding="utf-8") as f:
        SAMPLE_POLICIES = json.load(f).get("samples", [])
except Exception as e:
    print(f"Warning: Could not load sample policies: {e}")
    SAMPLE_POLICIES = []


# -------------------------------------------------------------
# FRONTEND STATIC ROUTES
# -------------------------------------------------------------

@app.route("/")
def serve_index():
    return send_from_directory(FRONTEND_DIR, "index.html")

@app.route("/scanner")
def serve_scanner():
    return send_from_directory(FRONTEND_DIR, "scanner.html")

@app.route("/results")
def serve_results():
    return send_from_directory(FRONTEND_DIR, "results.html")

@app.route("/history")
def serve_history():
    return send_from_directory(FRONTEND_DIR, "history.html")

@app.route("/about")
def serve_about():
    return send_from_directory(FRONTEND_DIR, "about.html")


# -------------------------------------------------------------
# REST API ENDPOINTS
# -------------------------------------------------------------

@app.route("/api/health", methods=["GET"])
def health_check():
    """Health & capability probe."""
    return jsonify({
        "status": "healthy",
        "app": "T&C Red Flag Scanner",
        "team": "CorruptX",
        "version": "1.0.0",
        "offline_capable": True,
        "engine": "Modular Cybersecurity Rule-Based NLP",
        "active_categories": len(analyzer.categories)
    })

@app.route("/api/rules", methods=["GET"])
def get_rules():
    """Return active risk taxonomy and scoring rules."""
    return jsonify(analyzer.rules_data)

@app.route("/api/demo", methods=["GET"])
def get_demo_policies():
    """Return realistic demo policies for instant hackathon evaluation."""
    return jsonify({
        "status": "success",
        "count": len(SAMPLE_POLICIES),
        "samples": SAMPLE_POLICIES
    })

@app.route("/api/scan", methods=["POST"])
def scan_policy():
    """
    Main analysis endpoint.
    Accepts JSON body: { "text": "...", "document_name": "..." }
    or multipart file upload with key 'file' and optional 'document_name'.
    """
    try:
        raw_text = ""
        doc_name = "Submitted Document"

        # 1. Check if multipart file upload
        if "file" in request.files:
            uploaded_file = request.files["file"]
            filename = uploaded_file.filename or "uploaded_policy.txt"
            doc_name = request.form.get("document_name", filename)

            content_bytes = uploaded_file.read()
            # Try utf-8 decoding, fallback to latin-1
            try:
                file_content = content_bytes.decode("utf-8")
            except UnicodeDecodeError:
                file_content = content_bytes.decode("latin-1", errors="ignore")

            # If HTML, strip tags cleanly with BeautifulSoup
            if filename.lower().endswith((".html", ".htm")):
                soup = BeautifulSoup(file_content, "html.parser")
                # Remove scripts and styles
                for script in soup(["script", "style", "meta", "noscript"]):
                    script.extract()
                raw_text = soup.get_text(separator="\n\n")
            else:
                raw_text = file_content

        # 2. Check if JSON payload
        elif request.is_json:
            data = request.get_json(silent=True) or {}
            raw_text = data.get("text", "")
            doc_name = data.get("document_name", "Pasted Policy")

        # 3. Check form data
        elif request.form:
            raw_text = request.form.get("text", "")
            doc_name = request.form.get("document_name", "Submitted Policy")

        # Edge case: Empty input
        if not raw_text or len(raw_text.strip()) == 0:
            return jsonify({
                "error": "Input text is empty. Please provide Terms & Conditions text or upload a document.",
                "risk_score": 0,
                "risk_level": "SAFE",
                "clauses_analyzed": 0,
                "red_flags": 0
            }), 400

        # Edge case: Extremely short text
        if len(raw_text.strip()) < 15:
            return jsonify({
                "error": "The supplied text is too short to perform a meaningful Terms & Conditions risk assessment.",
                "risk_score": 0,
                "risk_level": "SAFE",
                "clauses_analyzed": 0,
                "red_flags": 0
            }), 400

        # Safety limit for hackathon demo (e.g. max 500,000 chars)
        if len(raw_text) > 500000:
            raw_text = raw_text[:500000]

        # Perform analysis
        result = analyzer.scan(raw_text, doc_name)
        return jsonify(result), 200

    except Exception as e:
        print(f"Error during scan: {str(e)}", file=sys.stderr)
        return jsonify({
            "error": f"Internal scan engine exception: {str(e)}",
            "risk_score": 0,
            "risk_level": "ERROR"
        }), 500


# -------------------------------------------------------------
# ENTRY POINT
# -------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print("=" * 60)
    print(" CORRUPTX - T&C RED FLAG SCANNER")
    print(" Cybersecurity Hackathon Engine")
    print(f" Serving on http://127.0.0.1:{port}")
    print(" Offline capable: Yes (zero external cloud dependencies)")
    print("=" * 60)
    app.run(host="0.0.0.0", port=port, debug=True)
