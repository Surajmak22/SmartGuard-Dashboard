import sys
import os

# Add root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.api.main import app

# Vercel expects 'app' to be the variable name
# This handles requests to /api/
