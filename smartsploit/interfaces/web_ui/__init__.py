"""
SmartSploit Web UI
Flask-based web interface for the SmartSploit framework
"""

from .app import create_app
from .routes import main_bp

__all__ = ['create_app', 'main_bp']
