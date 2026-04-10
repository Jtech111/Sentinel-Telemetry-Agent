import json
import requests
import datetime
import hashlib
import hmac
import base64

# ==========================================
# 1. THE VAULT KEYS (Do not share these!)
# ==========================================
customer_id = 'YOUR_WORKSPACE_ID_HERE'
shared_key =  'YOUR_PRIMARY_KEY_HERE'
log_type = 'NomadMacTelemetry' # This is the name of the custom table Sentinel will create

# ==========================================
# 2. THE BRAIN: Gather Mac Telemetry
# ==========================================
print("Gathering network telemetry...")
try:
    # Ask a free API for our current IP and Location
    geo_req = requests.get('https://ipapi.co/json/', timeout=10)
    geo_data = geo_req.json()
    
    current_ip = geo_data.get('ip', 'Unknown')
    city = geo_data.get('city', 'Unknown')
    isp = geo_data.get('org', 'Unknown')
    
    print(f"Detected connection in {city} via {isp} (IP: {current_ip})")
except Exception as e:
    print("Failed to get IP data.")
    exit()

# Package it into the JSON envelope
payload = [{
    "DeviceName": "AXIOM-Mac-M3",
    "PublicIP": current_ip,
    "City": city,
    "ISP": isp,
    "Status": "Connected",
    "ThreatLevel": "Pending Analysis"
}]

body = json.dumps(payload)

# ==========================================
# 3. THE SECURITY SEAL: HMAC-SHA256 Signature
# ==========================================
# Azure requires us to mathematically encrypt a signature using our Primary Key
# so the vault knows it's actually us sending the data.
def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")  
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    authorization = "SharedKey {}:{}".format(customer_id,encoded_hash)
    return authorization

# ==========================================
# 4. THE ACTION: Send to Sentinel
# ==========================================
print("Encrypting signature and sending to Azure Vault...")
rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
content_length = len(body)
signature = build_signature(customer_id, shared_key, rfc1123date, content_length, 'POST', 'application/json', '/api/logs')

uri = f'https://{customer_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01'
headers = {
    'content-type': 'application/json',
    'Authorization': signature,
    'Log-Type': log_type,
    'x-ms-date': rfc1123date
}

response = requests.post(uri, data=body, headers=headers)

if (response.status_code >= 200 and response.status_code <= 299):
    print("SUCCESS: Telemetry accepted by Microsoft Sentinel!")
else:
    print(f"FAILED: Vault rejected the data. Code: {response.status_code}")
