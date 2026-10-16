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

app = create_app()
handler = app
