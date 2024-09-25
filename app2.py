from flask import Flask, jsonify, session
from config import SECRET_KEY, DEBUG, PORT
import logging
from logging.handlers import RotatingFileHandler
from routes2 import routes
from models import db, init_db

try:
    from flask_wtf.csrf import CSRFProtect
    csrf_enabled = True
except ImportError:
    print("Warning: Flask-WTF not found. CSRF protection is disabled.")
    csrf_enabled = False

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = SECRET_KEY
    
    if csrf_enabled:
        csrf = CSRFProtect(app)

    # Configure logging
    configure_logging(app)

    # Initialize database
    init_db(app)

    # Register error handlers
    register_error_handlers(app)

    # Register all routes
    app.register_blueprint(routes)

    return app

def configure_logging(app):
    if not app.debug:
        file_handler = RotatingFileHandler('app.log', maxBytes=10240, backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)

    # Add a stream handler to also log to console
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')
    console.setFormatter(formatter)
    app.logger.addHandler(console)

    app.logger.setLevel(logging.DEBUG)

def register_error_handlers(app):
    @app.errorhandler(400)
    @app.errorhandler(404)
    @app.errorhandler(500)
    def error_handler(error):
        app.logger.error(f"Error occurred: {error}")
        return jsonify(error=str(error)), error.code if hasattr(error, 'code') else 500

    @app.errorhandler(Exception)
    def handle_exception(e):
        app.logger.error(f"Unhandled exception: {str(e)}", exc_info=True)
        return jsonify(error="An unexpected error occurred"), 500

if __name__ == '__main__':
    app = create_app()
    app.run(debug=DEBUG, port=PORT)