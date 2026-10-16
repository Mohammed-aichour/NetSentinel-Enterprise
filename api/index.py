"""
NetSentinel Enterprise - Vercel Serverless Function Entrypoint
Initializes and exports WSGI application instance for Vercel Python runtime.
Author: Mohammed Aichour
"""

import sys
from pathlib import Path

# Ensure application root directory is available in Python path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend.app import create_app

raw_app = create_app()


class VercelWSGIAdapter:
    """
    WSGI Adapter for Vercel Python Serverless Runtime.
    Normalizes PATH_INFO when Vercel rewrites or mounts functions:
    1. If PATH_INFO is the script/destination name, recovers original URI
       from RAW_URI, REQUEST_URI, HTTP_X_FORWARDED_URI, or HTTP_X_MATCHED_PATH.
    2. If PATH_INFO was stripped to /v1/..., ensures /api prefix is available.
    3. Guarantees Flask receives the expected routes.
    """
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        path_info = environ.get("PATH_INFO", "")

        # If PATH_INFO is the serverless entrypoint destination, recover original URI
        if path_info in ("/api/index", "/api/index.py", "/index.py", "/index", ""):
            raw = (
                environ.get("RAW_URI") or
                environ.get("REQUEST_URI") or
                environ.get("HTTP_X_FORWARDED_URI") or
                environ.get("HTTP_X_MATCHED_PATH") or
                ""
            )
            if raw:
                clean_path = raw.split("?")[0]
                if clean_path:
                    path_info = clean_path

        # Normalize /v1/... to /api/v1/... for universal routing
        if path_info.startswith("/v1/"):
            path_info = "/api" + path_info
        elif path_info == "/v1":
            path_info = "/api/v1"

        environ["PATH_INFO"] = path_info
        return self.wsgi_app(environ, start_response)


app = VercelWSGIAdapter(raw_app)
handler = app
