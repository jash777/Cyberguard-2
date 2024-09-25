import os
from dotenv import load_dotenv

# API configuration
API_KEY = os.getenv('API_KEY', 'alpha')
AGENT_PORT = int(os.getenv('AGENT_PORT', 5000))

# Flask configuration
SECRET_KEY = os.getenv('SECRET_KEY', os.urandom(24))

# Debug mode
DEBUG = os.getenv('DEBUG', 'False').lower() in ('true', '1', 't')

# Port
PORT = int(os.getenv('PORT', 5001))