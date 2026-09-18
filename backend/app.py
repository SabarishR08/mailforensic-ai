"""
AI Email Threat Detection, GeoLocation & Forensic Intelligence Platform
Main Application Entry Point
"""

import os
import sys
from pathlib import Path
from flask import Flask, redirect, url_for
from dotenv import load_dotenv

load_dotenv()

# Ensure project root on path
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from backend.models import db
from backend.extensions import socketio
from backend.spa import spa_enabled, spa_index, spa_assets


def create_app():
    app = Flask(__name__, template_folder='../dashboard/templates', static_folder='../dashboard/static')

    app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'dev-secret-change-me')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///threat_logs.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['UPLOAD_FOLDER'] = os.path.join(project_root, 'uploads')
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    db.init_app(app)
    socketio.init_app(app)

    # Serve built React SPA assets (/assets/...) when present
    if spa_enabled():
        app.add_url_rule('/assets/<path:filename>', endpoint='spa_assets', view_func=spa_assets)

    # Register blueprints
    from backend.routes.dashboard import dashboard_bp
    from backend.routes.email import email_bp
    from backend.routes.forensic import forensic_bp
    from backend.routes.api import api_bp
    from backend.routes.extension import extension_bp

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(email_bp, url_prefix='/email')
    app.register_blueprint(forensic_bp, url_prefix='/forensic')
    app.register_blueprint(api_bp, url_prefix='/api')
    # Extension API: /check-url lives at the root by contract; the rest
    # of its routes carry their own /api/ prefix.
    app.register_blueprint(extension_bp)

    @app.route('/')
    def home():
        if spa_enabled():
            return spa_index()
        return redirect(url_for('dashboard.dashboard'))

    with app.app_context():
        db.create_all()
        try:
            from sqlalchemy import text
            db.session.execute(text("PRAGMA journal_mode=WAL;"))
            db.session.execute(text("PRAGMA synchronous=NORMAL;"))
            db.session.commit()
        except Exception:
            pass

    return app


if __name__ == '__main__':
    app = create_app()
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('DEBUG_MODE', 'true').lower() == 'true'
    socketio.run(app, host='0.0.0.0', port=port, debug=debug, allow_unsafe_werkzeug=True)
