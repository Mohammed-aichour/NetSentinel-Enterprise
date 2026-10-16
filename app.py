"""
NetSentinel Enterprise - Root Quick-Start Launcher
Run with: python app.py
"""

from backend.app import create_app
from backend.config import HOST, PORT, DEBUG

if __name__ == "__main__":
    app = create_app()
    app.run(host=HOST, port=PORT, debug=DEBUG)
