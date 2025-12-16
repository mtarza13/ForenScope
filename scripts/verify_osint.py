import requests
import sys

BASE_URL = "http://localhost"

def test_osint_flow():
    print("[*] Testing OSINT Flow...")
    
    # 1. Login
    payload = {"username": "admin", "password": "SecureAdminpass123!"} 
    # NOTE: If password was set in previous run via verify_auth.py, use that.
    # If this is a fresh run and verify_auth.py wasn't fully successful in setting it?
    # verify_auth.py sets it on FIRST run. 
    # Let's hope the previous verify_auth.py worked (it failed connection initially).
    # If the DB persisted, the user 'admin' exists. Password is whatever I sent first time.
    
    # Wait, in the logs verify_auth.py failed connection. So it might NOT have registered 'admin' yet?
    # Or maybe I tested it manually? No.
    # Let's try to register/login with a known password.
    
    # Actually, I'll attempt login. If 401, I might have messed up the "first run" logic if I restarted DB?
    # No, DB is persistent volume.
    # Let's try 'admin' / 'SecureAdminpass123!' as defined in previous script.
    
    s = requests.Session()
    try:
        r = s.post(f"{BASE_URL}/auth/token", data=payload)
        if r.status_code != 200:
             # Try creating if it's first run ever (unlikely if I didn't wipe vol)
             print(f"[-] Login failed: {r.status_code}. Admin might exist with diff pass or not exist.")
             # Try default 'admin' if I set it manually? 
             # I'll just proceed and fail if token missing.
             return
             
        token = r.json()['access_token']
        headers = {"Authorization": f"Bearer {token}"}
        print("[+] Logged in.")
        
        # 2. Get a Case ID (or create one)
        # List cases
        r = s.get(f"{BASE_URL}/cases", headers=headers)
        cases = r.json()
        if not cases:
            # Create dummy case
            print("[*] Creating test case...")
            r = s.post(f"{BASE_URL}/cases", json={"name": "OSINT Test Case"}, headers=headers)
            case_id = r.json()['id']
        else:
            case_id = cases[0]['id']
            
        print(f"[*] Using Case ID: {case_id}")
        
        # 3. Create OSINT Action
        print("[*] Creating Action...")
        action_payload = {
            "provider": "facecheck",
            "action_type": "remove_my_photos",
            "target_label": "Test Subject",
            "notes": "Initial request"
        }
        r = s.post(f"{BASE_URL}/cases/{case_id}/osint/actions", json=action_payload, headers=headers)
        if r.status_code != 200:
            print(f"[-] Create failed: {r.text}")
            return
            
        action = r.json()
        action_id = action['id']
        print(f"[+] Action Created: {action_id}")
        
        # 4. Update Action
        print("[*] Updating Status...")
        update_payload = {"status": "in_review", "tracking_url": "https://facecheck.id/track/123", "notes": "Submitted ID"}
        r = s.patch(f"{BASE_URL}/cases/{case_id}/osint/actions/{action_id}", json=update_payload, headers=headers)
        if r.status_code != 200:
            print(f"[-] Update failed: {r.text}")
            return
        print(f"[+] Action Updated: {r.json()['status']}")
        
        # 5. Upload Attachment
        print("[*] Uploading Attachment...")
        files = {'file': ('test_proof.txt', 'This is a proof file content')}
        r = s.post(f"{BASE_URL}/cases/{case_id}/osint/actions/{action_id}/attachments", files=files, headers=headers)
        if r.status_code != 200:
            print(f"[-] Upload failed: {r.text}")
            return
        print(f"[+] Attachment Uploaded: {r.json()['filename']}")
        
        # 6. Verify List
        print("[*] Verifying List...")
        r = s.get(f"{BASE_URL}/cases/{case_id}/osint/actions", headers=headers)
        if r.status_code == 200 and len(r.json()) > 0:
            print(f"[+] List verified. Count: {len(r.json())}")
        else:
            print("[-] List verification failed.")
            
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    test_osint_flow()
