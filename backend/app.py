"""
NetSentinel Enterprise - Application Server & SOC Web Console Entrypoint
High-throughput telemetry collector, threat detection engine, and REST API.
Author: Mohammed Aichour
"""

import os
import sys
import logging
from pathlib import Path
from flask import Flask, send_from_directory, jsonify

# Add parent directory to path to ensure robust imports
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from backend.config import HOST, PORT, DEBUG, ENTERPRISE_NAME, SOC_NAME, VERSION, CORS_ORIGINS
from backend.database import init_db, DeviceRepository
from backend.engine.simulator import seed_enterprise_topology
from backend.routes.api import api_bp

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s]: %(message)s"
)
logger = logging.getLogger("netsentinel.server")


def create_app() -> Flask:
    """Application factory for NetSentinel Enterprise."""
    frontend_dir = BASE_DIR / "frontend"
    
    app = Flask(
        __name__,
        static_folder=str(frontend_dir),
        static_url_path=""
    )

    # Initialize Database Schema & Seed if fresh, with serverless resilience
    try:
        init_db()
        existing_devices = DeviceRepository.list_all()
        if not existing_devices:
            logger.info("Initializing baseline enterprise topology for UniversiaCorp...")
            seed_enterprise_topology()
    except Exception as e:
        logger.error(f"Database initialization warning on startup: {e}")

    # Register API Endpoints (both /api/v1 and /v1 for serverless/reverse proxy compatibility)
    app.register_blueprint(api_bp)
    app.register_blueprint(api_bp, name="api_v1_direct", url_prefix="/v1")

    # Cross-Origin Resource Sharing (CORS) Configuration
    @app.after_request
    def apply_cors_headers(response):
        response.headers["Access-Control-Allow-Origin"] = CORS_ORIGINS
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-API-Key, X-SOC-Operator"
        return response

    @app.route("/api/v1/<path:dummy>", methods=["OPTIONS"])
    def handle_options_preflight(dummy):
        return "", 204

    @app.route("/v1/<path:dummy>", methods=["OPTIONS"])
    def handle_options_preflight_v1(dummy):
        return "", 204

    # Web Dashboard Routes
    @app.route("/")
    def index():
        return send_from_directory(str(frontend_dir), "index.html")

    @app.route("/<path:filename>")
    def static_proxy(filename):
        return send_from_directory(str(frontend_dir), filename)

    @app.errorhandler(404)
    def handle_404(e):
        return jsonify({"error": "Resource not found", "path": str(e)}), 404

    @app.errorhandler(500)
    def handle_500(e):
        logger.error(f"Internal server error: {e}")
        return jsonify({"error": "Internal server error", "details": str(e)}), 500

    return app


if __name__ == "__main__":
    logger.info("=" * 70)
    logger.info(f"  {ENTERPRISE_NAME}")
    logger.info(f"  {SOC_NAME} - Version {VERSION}")
    logger.info("=" * 70)
    logger.info(f"Listening on http://{HOST}:{PORT}")
    
    app = create_app()
    app.run(host=HOST, port=PORT, debug=DEBUG)
