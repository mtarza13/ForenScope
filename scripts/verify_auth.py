import requests
import sys

BASE_URL = "http://localhost:8000"

def test_auth():
    print("[*] Testing Auth Flow...")
    
    # 1. Try Login with default admin (should be created on first attempt if emtpy users)
    # logic in auth.py: if 0 users and user=admin, create it.
    
    payload = {
        "username": "admin",
        "password": "change_me_immediately_or_else" # Wait I didn't set password. 
        # In auth.py route I used form_data.password.
        # But wait, what IS the password? 
        # I didn't hardcode it. I used whatever they submit as the password for the new admin?
        # Let's check auth.py route code again.
    }
    
    # 2. Check logic in auth.py
    # if count == 0 and form_data.username == "admin":
    #    hashed = get_password_hash(form_data.password) <<-- Uses submitted password!
    #    admin = User(..., hashed_password=hashed, ...)
    
    # So on first run, whatever password I send becomes the admin password.
    # Safe for local dev first run.
    
    # Use a secure password for this test
    payload['password'] = "SecureAdminpass123!"
    
    try:
        r = requests.post(f"{BASE_URL}/auth/token", data=payload)
        if r.status_code == 200:
            token = r.json()['access_token']
            print(f"[+] Login Successful. Token: {token[:10]}...")
            
            # 3. Verify /auth/me
            headers = {"Authorization": f"Bearer {token}"}
            r2 = requests.get(f"{BASE_URL}/auth/me", headers=headers)
            if r2.status_code == 200:
                print(f"[+] /auth/me Verified: {r2.json()}")
            else:
                 print(f"[-] /auth/me Failed: {r2.status_code} {r2.text}")
                 
        else:
             print(f"[-] Login Failed: {r.status_code} {r.text}")
             if r.status_code == 401:
                 # Maybe user already exists with diff password?
                 print("   (User might already exist)")

    except Exception as e:
        print(f"[-] Connection failed: {e}")

if __name__ == "__main__":
    test_auth()
