from flask import render_template, request, jsonify, session, abort,flash,redirect, url_for
from models import db, Agent, FirewallRule
from api import make_api_request
from datetime import datetime
import random
from functools import wraps
import requests
import logging
from logging.handlers import RotatingFileHandler
from contextlib import contextmanager
from sqlalchemy.orm import scoped_session
from flask import session as flask_session
from werkzeug.exceptions import BadRequest, NotFound, InternalServerError
from urllib.parse import urlencode

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Create a file handler
file_handler = RotatingFileHandler('debug.log', maxBytes=10485760, backupCount=5)
file_handler.setLevel(logging.DEBUG)

# Create a formatter
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)

# Add the file handler to the logger
logger.addHandler(file_handler)

@contextmanager
def db_session():
    session = scoped_session(db.session)
    try:
        yield session
        session.commit()
    except Exception as e:
        session.rollback()
        logger.error(f"Database error: {str(e)}")
        raise
    finally:
        session.remove()

def agent_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        logger.debug(f"Checking for selected agent in function: {f.__name__}")
        if 'selected_agent' not in session:
            logger.warning("Attempted to access agent-specific function without a selected agent")
            error_params = urlencode({'error': 'Please select an agent before accessing this page.'})
            return redirect(url_for('agents') + '?' + error_params)
        return f(*args, **kwargs)
    return decorated_function

def index():
    logger.debug("Rendering index page")
    return render_template('index.html')

def agents():
    logger.debug("Fetching agents from database")
    try:
        with db_session() as session:
            agents = session.query(Agent).all()
            agents_list = [agent.to_dict() for agent in agents]
        logger.info(f"Successfully fetched {len(agents)} agents")
        return render_template('agents.html', agents=agents_list)
    except Exception as e:
        logger.error(f"Error in agents view: {str(e)}")
        abort(500, description="An error occurred while fetching agents")

def select_agent(agent_id):
    logger.info(f"Selecting agent with ID: {agent_id}")
    try:
        with db_session() as session:
            agent = session.query(Agent).get(agent_id)
            if agent:
                flask_session['selected_agent_id'] = agent.id
                flask_session['selected_agent'] = agent.ip_address
                flask_session['selected_agent_name'] = agent.name
                logger.info(f"Agent selected successfully: {agent.name} ({agent.ip_address})")
                return jsonify({'message': 'Agent selected successfully', 'agent': agent.name}), 200
            else:
                logger.warning(f"Agent not found with ID: {agent_id}")
                abort(404, description="Agent not found")
    except Exception as e:
        logger.error(f"Error in select_agent: {str(e)}")
        abort(500, description="An error occurred while selecting the agent")

def users():
    logger.debug("Fetching users from agent")
    response, status_code = make_api_request('users')
    logger.info(f"Users API request status code: {status_code}")
    if isinstance(response, dict):
        users_list = response.get('users', [])
        error = response.get('error') if status_code != 200 else None
    else:
        users_list = []
        error = "Unexpected response format"
    return render_template('users.html', users=users_list, error=error)

def manage_agents():
    logger.debug(f"Managing agents: {request.method}")
    try:
        with db_session() as session:
            if request.method == 'GET':
                agents = session.query(Agent).all()
                logger.info(f"Fetched {len(agents)} agents")
                return jsonify([agent.to_dict() for agent in agents])
            elif request.method == 'POST':
                data = request.json
                if not data or 'name' not in data or 'ip_address' not in data:
                    raise BadRequest("Invalid agent data")
                new_agent = Agent(name=data['name'], ip_address=data['ip_address'], status='Unknown')
                session.add(new_agent)
                logger.info(f"Added new agent: {data['name']} ({data['ip_address']})")
                return jsonify({'message': 'Agent added successfully'}), 201
            elif request.method == 'DELETE':
                agent_id = request.args.get('id')
                if not agent_id:
                    raise BadRequest("Agent ID is required")
                agent = session.query(Agent).get(agent_id)
                if agent:
                    session.delete(agent)
                    logger.info(f"Removed agent with ID: {agent_id}")
                    return jsonify({'message': 'Agent removed successfully'}), 200
                else:
                    raise NotFound("Agent not found")
    except BadRequest as e:
        logger.warning(f"Bad request in manage_agents: {str(e)}")
        abort(400, description=str(e))
    except NotFound as e:
        logger.warning(f"Not found in manage_agents: {str(e)}")
        abort(404, description=str(e))
    except Exception as e:
        logger.error(f"Error in manage_agents: {str(e)}")
        abort(500, description="An error occurred while managing agents")

def check_agent_status(agent_id):
    logger.debug(f"Checking status for agent ID: {agent_id}")
    try:
        with db_session() as session:
            agent = session.query(Agent).get(agent_id)
            if not agent:
                logger.warning(f"Agent not found with ID: {agent_id}")
                abort(404, description="Agent not found")
            
            new_status = random.choice(['Active', 'Inactive', 'Unreachable'])
            agent.status = new_status
            agent.last_check = datetime.utcnow()
        logger.info(f"Updated status for agent {agent_id} to {new_status}")
        return jsonify({'status': new_status})
    except Exception as e:
        logger.error(f"Error in check_agent_status: {str(e)}")
        abort(500, description="An error occurred while checking agent status")

@agent_required
def processes():
    return render_template('processes.html')

# @agent_required
# def get_processes():
#     logger.debug("Fetching processes from agent")
#     try:
#         response, status_code = make_api_request('processes')
        
#         if status_code == 200:
#             processes = response.get('processes', [])
#             logger.info(f"Successfully retrieved {len(processes)} processes")
#             return jsonify(processes), 200
#         else:
#             logger.error(f"Failed to retrieve processes. Status code: {status_code}")
#             return jsonify({'error': 'Failed to retrieve processes'}), status_code
#     except Exception as e:
#         logger.exception(f"Unexpected error in get_processes route")
#         return jsonify({'error': 'An unexpected error occurred'}), 500

@agent_required
def get_processes():
    logger.info(f"Requesting processes from agent: {session['selected_agent']}")
    response, status_code = make_api_request('processes')
    
    if status_code != 200:
        logger.error(f"Error getting processes. Status code: {status_code}, Response: {response}")
        return jsonify({'error': 'Failed to retrieve processes'}), status_code
    
    if isinstance(response, dict) and 'processes' in response:
        processes = response['processes']
    elif isinstance(response, list):
        processes = response
    else:
        logger.error(f"Unexpected response format: {response}")
        return jsonify({'error': 'Unexpected response format'}), 500

    logger.info(f"Successfully retrieved {len(processes)} processes")
    return jsonify(processes), 200

def manage_users():
    logger.debug(f"Managing users: {request.method}")
    if request.method == 'GET':
        response, status_code = make_api_request('users')
    elif request.method == 'POST':
        data = request.json
        if not data or 'username' not in data:
            abort(400, description="Invalid user data")
        response, status_code = make_api_request('add_user', method='POST', data=data)
    elif request.method == 'DELETE':
        username = request.args.get('username')
        if not username:
            abort(400, description="Username is required")
        response, status_code = make_api_request(f"remove_user?username={username}", method='DELETE')
    else:
        logger.warning(f"Invalid method for manage_users: {request.method}")
        abort(405, description="Method not allowed")
    
    logger.info(f"Manage users API request status code: {status_code}")
    if isinstance(response, dict):
        return jsonify(response), status_code
    else:
        abort(500, description="Unexpected response format")

@agent_required
def services():
    return render_template('applications.html')

@agent_required
def get_services():
    logger.debug("Fetching services from agent")
    try:
        selected_agent = session.get('selected_agent')
        if not selected_agent:
            logger.warning("No agent selected when trying to fetch services")
            abort(400, description="No agent selected")

        logger.info(f"Fetching services for agent: {selected_agent}")
        
        response, status_code = make_api_request('services')
        
        if status_code == 200:
            services = response.get('services', [])
            logger.info(f"Successfully retrieved {len(services)} services for agent {selected_agent}")
            return jsonify({'services': services}), 200
        else:
            logger.error(f"Failed to retrieve services for agent {selected_agent}. Status code: {status_code}")
            abort(status_code, description="Failed to retrieve services")
    except Exception as e:
        logger.exception(f"Unexpected error in get_services route for agent {session.get('selected_agent')}")
        abort(500, description="An unexpected error occurred while retrieving services")

@agent_required
def block_port():
    logger.debug("Blocking port")
    port_data = request.json
    if not port_data or 'port' not in port_data:
        logger.warning("Port number is missing in the request")
        abort(400, description="Port number is required")

    port = port_data['port']
    if not isinstance(port, int) or port < 1 or port > 65535:
        logger.warning(f"Invalid port number: {port}")
        abort(400, description="Invalid port number")

    response, status_code = make_api_request('block_port', method='POST', data={'port': port})
    
    if status_code == 200:
        if isinstance(response, dict) and response.get('status') == 'success':
            logger.info(f"Successfully blocked port {port}")
            return jsonify({'status': 'success', 'message': f'Port {port} blocked successfully'}), 200
        else:
            logger.warning(f"Port {port} blocked with a note: {response.get('message', 'Unknown response from agent')}")
            return jsonify({'status': 'success', 'message': f'Port {port} blocked, but with a note: {response.get("message", "Unknown response from agent")}'})
    else:
        logger.error(f"Failed to block port {port}. Status code: {status_code}")
        abort(status_code, description=f"Failed to block port {port}. Agent response: {response.get('message', 'Unknown error')}")

def firewall():
    logger.info("Entering firewall function")
    
    try:
        with db_session() as session:
            agents = session.query(Agent.id, Agent.name, Agent.ip_address).all()
        
        logger.info(f"Fetched {len(agents)} agents from the database")
        
        rules = {}
        selected_agent_id = flask_session.get('selected_agent_id')
        selected_agent_ip = flask_session.get('selected_agent')
        
        logger.info(f"Selected agent ID: {selected_agent_id}, IP: {selected_agent_ip}")
        
        if selected_agent_ip:
            logger.info(f"Attempting to fetch rules for agent {selected_agent_ip}")
            response, status_code = make_api_request('iptables_rules')
            logger.info(f"API response status code: {status_code}")
            
            if status_code == 200 and isinstance(response, dict) and response.get('status') == 'success':
                rules = response.get('rules', {})
                logger.info(f"Fetched firewall rules from the agent")
            else:
                logger.error(f"Failed to fetch firewall rules. Status code: {status_code}, Response: {response}")
        else:
            logger.warning("No agent selected, skipping firewall rules fetch")
        
        logger.info(f"Rendering firewall template with {len(agents)} agents and rules for {len(rules)} tables")
        return render_template('firewall.html', agents=agents, rules=rules, selected_agent_id=selected_agent_id)
    except Exception as e:
        logger.error(f"Error in firewall function: {str(e)}")
        abort(500, description="An error occurred while fetching firewall data")

@agent_required
def manage_firewall_rules():
    logger.debug(f"Managing firewall rules: {request.method}")
    if request.method == 'GET':
        response, status_code = make_api_request('iptables_rules')
        if status_code == 200 and isinstance(response, dict) and response.get('status') == 'success':
            logger.info("Successfully fetched firewall rules")
            return jsonify(response.get('rules', {})), 200
        logger.error(f"Failed to fetch firewall rules. Status code: {status_code}")
        abort(status_code, description="Failed to fetch firewall rules")
    
    elif request.method == 'POST':
        rule_data = request.json
        if not rule_data or not isinstance(rule_data, dict):
            abort(400, description="Invalid rule data")
        logger.info(f"Applying new firewall rule: {rule_data}")
        response, status_code = make_api_request('apply-rules', method='POST', data={'rules': [rule_data]})
        return jsonify(response), status_code
    
    elif request.method == 'DELETE':
        rule_data = request.json
        if not rule_data or not isinstance(rule_data, dict):
            abort(400, description="Invalid rule data")
        logger.info(f"Removing firewall rule: {rule_data}")
        response, status_code = make_api_request('remove-rule', method='POST', data=rule_data)
        return jsonify(response), status_code
    
    else:
        logger.warning(f"Invalid method for manage_firewall_rules: {request.method}")
        abort(405, description="Method not allowed")

def fetch_and_reapply_rules():
    logger.info("Fetching and reapplying firewall rules")
    try:
        with db_session() as session:
            rules = session.query(FirewallRule).all()
        
        logger.info(f"Fetched {len(rules)} rules from database")
        response, status_code = make_api_request('apply-rules', method='POST', data={'rules': [rule.to_dict() for rule in rules]})
        
        if status_code != 200:
            logger.error(f"Failed to reapply rules. Status code: {status_code}, Response: {response}")
            abort(status_code, description="Failed to reapply rules")
        
        logger.info("Successfully reapplied firewall rules")
        return jsonify({'message': 'Rules reapplied successfully'}), 200
    except Exception as e:
        logger.error(f"Error in fetch_and_reapply_rules: {str(e)}")
        abort(500, description="An error occurred while reapplying rules")

def get_selected_agent():
    logger.debug("Getting selected agent information")
    selected_agent = flask_session.get('selected_agent')
    selected_agent_name = flask_session.get('selected_agent_name')
    
    if selected_agent and selected_agent_name:
        logger.info(f"Selected agent: {selected_agent_name} ({selected_agent})")
        return jsonify({
            'selected_agent': {
                'name': selected_agent_name,
                'ip_address': selected_agent
            }
        })
    else:
        logger.warning("No agent selected")
        return jsonify({'selected_agent': None}), 404

@agent_required
def applications():
    logger.debug("Fetching services from agent")
    response, status_code = make_api_request('services')
    logger.info(f"Services API request status code: {status_code}")
    
    if status_code == 200 and response.get('status') == 'success':
        services = response.get('services', [])
        error = None
    else:
        services = []
        error = response.get('message', 'An error occurred while retrieving services')
        logger.error(f"Error fetching services: {error}")
    
    return render_template('applications.html', services=services, error=error)

@agent_required
def get_services():
    logger.debug("Fetching services from agent")
    response, status_code = make_api_request('services')
    logger.info(f"Services API request status code: {status_code}")
    
    if status_code != 200:
        logger.error(f"Error fetching services. Status code: {status_code}, Response: {response}")
        abort(status_code, description="Failed to retrieve services")
    
    return jsonify(response), status_code

def error_handler(error):
    logger.error(f"Error occurred: {error}")
    return jsonify(error=str(error)), error.code if hasattr(error, 'code') else 500
