"""Vercel entry point: exposes the stateless FastAPI app as one serverless function."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from web.serverless import app  # noqa: E402,F401
