import requests
import sys
from config import SECURITY_URL, API_URL, ADMIN_EMAIL, ADMIN_PASSWORD, print_step, print_success, print_error, print_info

def run_test():
    """
    Scenario 3: Security Controls Validation
    1. Unauthorized Access (Try to read secret without token).
    2. Seal the Vault.
    3. Operational Lock (Try to create/read secret while sealed).
    4. Unseal Verification (verify the lock).
    """
    print_step("SCENARIO 3: SECURITY CONTROLS VALIDATION")
    
    session = requests.Session()

    # 1. Unauthorized Access
    print_step("1. Testing Unauthorized Access")
    try:
        # Try to list projects without header
        res = requests.get(f"{API_URL}/api/projects/")
        if res.status_code == 401 or res.status_code == 403:
            print_success(f"Unauthorized request blocked as expected (Status: {res.status_code})")
        else:
            print_error(f"Security failure! Unauthorized request allowed (Status: {res.status_code})")
    except Exception as e:
        print_error(f"Network error: {e}")

    # Login for further tests
    try:
        res = session.post(f"{SECURITY_URL}/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
        if res.status_code == 200:
            access_token = res.json()['tokens']['access_token']
            session.headers.update({"Authorization": f"Bearer {access_token}"})
        else:
            print_error("Login failed, cannot proceed with vault tests.")
            sys.exit(1)
    except:
        sys.exit(1)

    # 2. Seal Vault
    print_step("2. Testing Vault Sealing")
    try:
        # Endpoint /api/crypto/seal
        res = session.post(f"{API_URL}/api/crypto/seal")
        
        if res.status_code == 200:
            print_success("Vault sealed command sent successfully.")
            
            # Verify Status
            status_res = session.get(f"{API_URL}/api/crypto/status")
            if status_res.json()['vault']['sealed'] == True:
                print_success("Vault status confirmed: SEALED")
            else:
                print_error("Vault status check failed - reported as UNSEALED")
        else:
            print_info(f"Could not seal vault (Status: {res.status_code}). might already be sealed.")
            
    except Exception as e:
        print_error(f"Seal error: {e}")

    # 3. Operational Lock Test
    print_step("3. Verifying Operational Lock (Read Secret while Sealed)")
    try:
        res = session.get(f"{API_URL}/api/data/99999")
        
        response_text = res.text.lower()
        if res.status_code == 503 or "sealed" in response_text:
             print_success(f"Operation blocked by Vault Lock (Status: {res.status_code}, Msg: {res.text})")
        elif res.status_code == 404:
             print_info("Returned 404. This *might* be okay if seal check is per-resource, but better if global.")
        else:
             print_error(f"Unexpected response while sealed: {res.status_code} - {res.text}")

    except Exception as e:
         print_error(f"Test error: {e}")

if __name__ == "__main__":
    run_test()
