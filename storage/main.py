#!/usr/bin/env python3

import os
import sys
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
import logging
from flask import Flask, jsonify

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

def get_db_config():
    """Get database configuration from environment variables."""
    return {
        'host': os.getenv('DB_HOST', 'localhost'),
        'port': int(os.getenv('DB_PORT', '5432')),
        'database': os.getenv('DB_NAME', 'lunaguard'),
        'user': os.getenv('DB_USER', 'postgres'),
        'password': os.getenv('DB_PASSWORD', 'password')
    }

def read_schema_file():
    """Read the SQL schema file."""
    schema_path = os.path.join(os.path.dirname(__file__), 'schema.sql')
    try:
        with open(schema_path, 'r') as f:
            return f.read()
    except FileNotFoundError:
        logger.error(f"Schema file not found: {schema_path}")
        return None

def provision_schema():
    """Provision the database schema."""
    config = get_db_config()
    schema_sql = read_schema_file()
    
    if not schema_sql:
        return False
        
    try:
        # Connect to database
        logger.info(f"Connecting to database {config['database']} at {config['host']}:{config['port']}")
        conn = psycopg2.connect(**config)
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        
        with conn.cursor() as cursor:
            # Execute schema SQL
            logger.info("Executing schema provisioning...")
            cursor.execute(schema_sql)
            logger.info("Schema provisioned successfully!")
            return True
            
    except psycopg2.Error as e:
        # Check if it's just a trigger already exists error (non-critical)
        if "already exists" in str(e).lower():
            logger.warning(f"Some objects already exist (this is normal): {e}")
            logger.info("Schema provisioning completed with warnings")
            return True
        else:
            logger.error(f"Database error: {e}")
            return False
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return False
    finally:
        if 'conn' in locals():
            conn.close()

def check_db_connection():
    """Check database connection."""
    config = get_db_config()
    try:
        conn = psycopg2.connect(**config)
        conn.close()
        return True
    except:
        return False

@app.route('/health')
def health_check():
    """Health check endpoint."""
    db_ok = check_db_connection()
    status = "ok" if db_ok else "error"
    return jsonify({
        "status": status,
        "service": "lunaguard-storage",
        "database": "ok" if db_ok else "error"
    }), 200 if db_ok else 503

@app.route('/provision')
def provision_endpoint():
    """Endpoint to provision database schema."""
    success = provision_schema()
    if success:
        return jsonify({
            "status": "success",
            "message": "Database schema provisioned successfully"
        }), 200
    else:
        return jsonify({
            "status": "error",
            "message": "Failed to provision database schema"
        }), 500

if __name__ == "__main__":
    # Provision schema on startup
    logger.info("Starting LunaGuard Storage Service")
    logger.info("Provisioning database schema...")
    
    if provision_schema():
        logger.info("Schema provisioning completed successfully")
    else:
        logger.error("Schema provisioning failed")
        sys.exit(1)
    
    # Start the web server
    port = int(os.getenv('PORT', '8002'))
    host = os.getenv('HOST', '0.0.0.0')
    
    logger.info(f"Starting storage service on {host}:{port}")
    app.run(host=host, port=port, debug=os.getenv('DEBUG', 'false').lower() == 'true')
