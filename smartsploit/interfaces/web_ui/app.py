"""
Flask Application Factory for SmartSploit Web UI
"""

import os
import logging
from flask import Flask
from smartsploit.core.framework import get_framework

def create_app(config_name=None):
    """Create and configure Flask application"""
    app = Flask(__name__)
    
    # Configure app
    app.config['SECRET_KEY'] = os.environ.get('SESSION_SECRET', 'smartsploit-dev-key-2025')
    app.config['DEBUG'] = True
    
    # Initialize framework
    framework = get_framework()
    app.framework = framework
    
    # Register blueprints
    from .routes import main_bp
    app.register_blueprint(main_bp)
    
    # Configure logging
    logging.basicConfig(level=logging.DEBUG)
    
    return app
