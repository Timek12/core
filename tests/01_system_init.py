import requests
import sys
from config import SECURITY_URL, API_URL, ADMIN_EMAIL, ADMIN_PASSWORD, ADMIN_NAME, print_step, print_success, print_error, print_info

def run_test():
    """
    Scenario 1: System Initialization and Unsealing
    1. Register a new admin user.
    2. Login to get Access Token.
    3. Check Vault Status.
    4. Initialize Vault (if needed) -> Get Master Key & Root Token.
    5. Unseal Vault using Master Key.
    6. Verify System is Operational.
    """
    print_step("SCENARIO 1: SYSTEM INITIALIZATION AND UNSEALING")
    
    session = requests.Session()
    
    # 1. Register
    print_info("Attempting to register admin user...")
    try:
        reg_payload = {
            "email": ADMIN_EMAIL,
            "password": ADMIN_PASSWORD,
            "name": ADMIN_NAME
        }
        res = session.post(f"{SECURITY_URL}/auth/register", json=reg_payload)
        
        if res.status_code == 201:
            print_success("User registered successfully.")
        elif res.status_code == 400 and "already exists" in res.text:
            print_info("User already exists, proceeding to login.")
        else:
            print_error(f"Registration failed: {res.status_code} {res.text}")
            sys.exit(1)
            
    except Exception as e:
        print_error(f"Connection failed: {e}")
        sys.exit(1)

    # 2. Login
    print_info("Logging in...")
    try:
        login_payload = {
            "email": ADMIN_EMAIL,
            "password": ADMIN_PASSWORD
        }
        res = session.post(f"{SECURITY_URL}/auth/login", json=login_payload)
        
        if res.status_code == 200:
            data = res.json()
            access_token = data['tokens']['access_token']
            session.headers.update({"Authorization": f"Bearer {access_token}"})
            print_success("Login successful. Token acquired.")
        else:
            print_error(f"Login failed: {res.status_code} {res.text}")
            sys.exit(1)
            
    except Exception as e:
        print_error(f"Login connection failed: {e}")
        sys.exit(1)

    # 3. Check Vault Status
    print_info("Checking Vault Status...")
    try:
        res = session.get(f"{API_URL}/api/crypto/status")
        if res.status_code != 200:
            print_error(f"Failed to get vault status: {res.status_code}")
            sys.exit(1)
            
        status = res.json()
        vault_status = status.get('vault', {})
        print_info(f"Current Status: Initialized={vault_status.get('initialized')}, Sealed={vault_status.get('sealed')}")
        
        master_key = None
        
        # 4. Initialize if needed
        if not vault_status.get('initialized'):
            print_step("Initializing Vault...")
            
            payload = {"external_token": "MrXMucCLlmBOLI6jZEhppdGvJZJosAc5"}
            res = session.post(f"{API_URL}/api/crypto/init", json=payload)
            
            if res.status_code == 200:
                init_data = res.json()
                print_success(f"Vault Initialized. {init_data.get('message')}")
            elif res.status_code == 403:
                print_error("Initialization blocked: Admin privileges required.")
                print_info("The registered user needs 'admin' role. Please update the user role in database or use existing admin.")
                sys.exit(1)
            else:
                print_error(f"Initialization failed: {res.status_code} {res.text}")
                sys.exit(1)
        else:
            print_info("Vault already initialized.")

        # 5. Check Seal Status and Unseal if needed
        # Refresh status after potential initialization
        res = session.get(f"{API_URL}/api/crypto/status")
        if res.status_code == 200:
             vault_status = res.json().get('vault', {})
        
        if vault_status.get('sealed'):
            print_step("Attempting to Unseal with Test Token...")
            unseal_payload = {"external_token": "MrXMucCLlmBOLI6jZEhppdGvJZJosAc5"}
            res = session.post(f"{API_URL}/api/crypto/unseal", json=unseal_payload)
            
            if res.status_code == 200:
                 print_success("Vault Unsealed successfully.")
            elif res.status_code == 403:
                 print_error("Unseal blocked: Admin privileges required or Invalid Token.")
                 print_info("Ensure user is Admin and external_token is correct.")
                 sys.exit(1)
            else:
                 print_error(f"Unseal failed: {res.status_code} {res.text}")
                 sys.exit(1)
        else:
            print_success("Vault is already UNSEALED. Ready for operations.")

    except Exception as e:
        print_error(f"Vault operations failed: {e}")
        sys.exit(1)

    except Exception as e:
        print_error(f"Vault operations failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    run_test()
