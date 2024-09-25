from flask import Flask, jsonify
from config import SECRET_KEY, DEBUG, PORT
import logging
from logging.handlers import RotatingFileHandler
from routes import *
from models import db, init_db

def create_app():
    app = Flask(__name__)
    app.secret_key = SECRET_KEY

    # Configure logging
    configure_logging(app)

    # Initialize database
    init_db(app)

    # Register routes
    register_routes(app)

    # Register error handlers
    register_error_handlers(app)

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

def register_routes(app):
    # Main routes
    app.add_url_rule('/', 'index', index)
    app.add_url_rule('/agents', 'agents', agents)
    app.add_url_rule('/select_agent/<int:agent_id>', 'select_agent', select_agent, methods=['POST', 'GET'])
    app.add_url_rule('/users', 'users', users)
    app.add_url_rule('/firewall', 'firewall', firewall)
    app.add_url_rule('/processes', 'processes', processes)
    app.add_url_rule('/block_port', 'block_port', block_port)
    app.add_url_rule('/services', 'services', services)


    # API routes
    app.add_url_rule('/api/agents', 'manage_agents', manage_agents, methods=['GET', 'POST', 'DELETE'])
    app.add_url_rule('/api/check_agent_status/<int:agent_id>', 'check_agent_status', check_agent_status)
    app.add_url_rule('/api/processes', 'get_processes', get_processes)
    app.add_url_rule('/api/users', 'manage_users', manage_users, methods=['GET', 'POST', 'DELETE'])
    app.add_url_rule('/api/firewall_rules', 'manage_firewall_rules', manage_firewall_rules, methods=['GET', 'POST', 'DELETE'])
    app.add_url_rule('/api/selected_agent', 'get_selected_agent', get_selected_agent)
    app.add_url_rule('/api/block_port', 'api_block_port', block_port, methods=['POST', 'GET'])
    app.add_url_rule('/api/services', 'get_services', get_services, methods=['GET'])


def error_handler(error):
    app.logger.error(f"Error occurred: {error}")
    return jsonify(error=str(error)), error.code if hasattr(error, 'code') else 500

def handle_exception(e):
    app.logger.error(f"Unhandled exception: {str(e)}", exc_info=True)
    return jsonify(error="An unexpected error occurred"), 500

def register_error_handlers(app):
    app.register_error_handler(400, error_handler)
    app.register_error_handler(404, error_handler)
    app.register_error_handler(500, error_handler)
    app.errorhandler(Exception)(handle_exception)

if __name__ == '__main__':
    app = create_app()
    app.run(debug=DEBUG, port=PORT)