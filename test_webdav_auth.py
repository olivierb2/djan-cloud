#!/usr/bin/env python3

import requests
import base64
import sys

def test_webdav_auth():
    # Test WebDAV authentication
    username = "root"
    password = input(f"Enter password for user '{username}': ")
    
    # Encode credentials for Basic Auth
    credentials = f"{username}:{password}"
    encoded_credentials = base64.b64encode(credentials.encode('utf-8')).decode('ascii')
    
    headers = {
        'Authorization': f'Basic {encoded_credentials}',
        'User-Agent': 'WebDAV-Test-Client/1.0'
    }
    
    # Test URL - adjust port if needed
    url = "http://127.0.0.1:8000/remote.php/webdav/files/root/"
    
    print(f"Testing WebDAV authentication to: {url}")
    print(f"Using credentials: {username}:{password[:2]}{'*' * (len(password) - 2)}")
    
    try:
        response = requests.request('PROPFIND', url, headers=headers, timeout=10)
        
        print(f"\nResponse Status: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")
        print(f"Response Body: {response.text[:500]}")
        
        if response.status_code == 401:
            print("\n❌ Authentication failed!")
            print("Possible issues:")
            print("- Incorrect password")
            print("- User doesn't exist")
            print("- Django authentication backend issue")
        elif response.status_code == 207:
            print("\n✅ Authentication successful!")
        else:
            print(f"\n⚠️  Unexpected status code: {response.status_code}")
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Request failed: {e}")
        print("Make sure Django development server is running on http://127.0.0.1:8000")

if __name__ == "__main__":
    test_webdav_auth()