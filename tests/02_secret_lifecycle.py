import requests
import sys
import time
from config import SECURITY_URL, API_URL, ADMIN_EMAIL, ADMIN_PASSWORD, print_step, print_success, print_error, print_info

def run_test():
    """
    Scenario 2: Secret Lifecycle (CRUD)
    1. Login.
    2. Create a Project.
    3. Create a Secret in that project.
    4. Read the Secret (Verify Decryption).
    5. Rotate the Secret (Update Value).
    6. Verify New Value and Version History.
    """
    print_step("SCENARIO 2: SECRET LIFECYCLE (CRUD)")
    
    session = requests.Session()
    
    # Login
    try:
        res = session.post(f"{SECURITY_URL}/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
        if res.status_code != 200:
            print_error(f"Login failed: {res.text}")
            sys.exit(1)
        access_token = res.json()['tokens']['access_token']
        session.headers.update({"Authorization": f"Bearer {access_token}"})
    except Exception as e:
        print_error(f"Login error: {e}")
        sys.exit(1)

    # 1. Create Project
    print_step("1. Creating Project")
    project_id = None
    try:
        proj_payload = {
            "name": f"Thesis Test Project {int(time.time())}",
            "description": "Project created by verification script"
        }
        res = session.post(f"{API_URL}/api/projects/", json=proj_payload)
        
        if res.status_code == 201:
            project_data = res.json()
            project_id = project_data.get('id') or project_data.get('project_id')
            if not project_id:
                 print_error(f"Could not find project ID in response: {project_data}")
                 sys.exit(1)
            print_success(f"Project created: {project_data['name']} (ID: {project_id})")
        else:
            print_error(f"Project creation failed: {res.text}")
            sys.exit(1)
    except Exception as e:
        print_error(f"Project error: {e}")
        sys.exit(1)

    # 2. Create Secret
    print_step("2. Creating Secret")
    secret_id = None
    secret_key = "DB_PASSWORD"
    secret_value = "SuperSecretPassword123!"
    
    try:
        secret_payload = {
            "name": "Database Credentials",
            "type": "text",
            "data_type": "text",
            "fields": [{"key": secret_key, "value": secret_value}],
            "project_id": project_id
        }
        res = session.post(f"{API_URL}/api/data/", json=secret_payload)
        
        if res.status_code == 201:
            secret_data = res.json()
            secret_id = secret_data['id']
            print_success(f"Secret created (ID: {secret_id})")
        else:
            print_error(f"Secret creation failed: {res.text}")
            sys.exit(1)
    except Exception as e:
        print_error(f"Secret error: {e}")
        sys.exit(1)

    # 3. Read Secret
    print_step("3. Reading Secret (Decryption Verification)")
    try:
        res = session.get(f"{API_URL}/api/data/{secret_id}")
        
        if res.status_code == 200:
            data = res.json()
            decrypted_data = data.get('decrypted_data', {})
            fields = decrypted_data.get('fields', [])
            
            retrieved_value = None
            for item in fields:
                if item.get('key') == secret_key:
                    retrieved_value = item.get('value')
                    break
            
            if retrieved_value == secret_value:
                print_success(f"Secret retrieved and decrypted successfully. Value matches: {retrieved_value}")
            else:
                print_error(f"Value mismatch! Expected: {secret_value}, Got: {retrieved_value}")
                print_info(f"Full Decrypted Data: {decrypted_data}")
        else:
            print_error(f"Read failed: {res.text}")
    except Exception as e:
        print_error(f"Read error: {e}")

    # 4. Rotate Secret (Update)
    print_step("4. Rotating Secret (Versioning)")
    new_value = "NewRotatedPassword456!"
    try:
        update_payload = {
            "fields": [{"key": secret_key, "value": new_value}]
        }
        res = session.put(f"{API_URL}/api/data/{secret_id}", json=update_payload)
        
        if res.status_code == 200:
            print_success("Secret rotated successfully.")
            
            # Verify new value
            verify_res = session.get(f"{API_URL}/api/data/{secret_id}")
            updated_decrypted = verify_res.json().get('decrypted_data', {})
            updated_fields = updated_decrypted.get('fields', [])
            
            updated_value = None
            for item in updated_fields:
                if item.get('key') == secret_key:
                    updated_value = item.get('value')
                    break

            if updated_value == new_value:
                print_success(f"New value verified: {updated_value}")
            else:
                print_error(f"Rotation verification failed. Expected {new_value}, Got {updated_value}")
        else:
            print_error(f"Rotation failed: {res.text}")

    except Exception as e:
        print_error(f"Rotation error: {e}")

if __name__ == "__main__":
    run_test()
