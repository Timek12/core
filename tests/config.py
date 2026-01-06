import os

# Configuration for Test Scripts

# Security Service 
SECURITY_URL = os.getenv("SECURITY_URL", "http://localhost:8001")

# Server Service
API_URL = os.getenv("API_URL", "http://localhost:8000")

# Test Credentials
# Using the default admin account created by seed.py
ADMIN_EMAIL = "admin@luna.com"
ADMIN_PASSWORD = "Admin123@"
ADMIN_NAME = "Admin User"

# Colors for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_step(msg):
    print(f"\n{Colors.HEADER}=== {msg} ==={Colors.ENDC}")

def print_success(msg):
    print(f"{Colors.OKGREEN}✓ {msg}{Colors.ENDC}")

def print_error(msg):
    print(f"{Colors.FAIL}✗ {msg}{Colors.ENDC}")

def print_info(msg):
    print(f"{Colors.OKBLUE}ℹ {msg}{Colors.ENDC}")
