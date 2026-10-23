#!/usr/bin/env python3
import sys
import os

# Ensure parent directory is in sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Re-export handler from scan.py so Vercel can find it at default api/index.py
from api.scan import handler

# Also expose 'app' alias in case a WSGI/ASGI runner inspects it
app = handler
