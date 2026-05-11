import sys
import os
import uuid
import threading
import time
import random
import base64
import re
import json
from pathlib import Path
from flask import Flask, request, Response
import requests
import urllib3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from werkzeug.serving import run_simple

# Try to import proto modules
try:
    from src.core.majorlogin_ob53_pb2 import MajorLoginOb53, MajorLoginResOb53
    from src.core.login_pb2 import getUID, LoginReq
    from src.utils.proto_utils import ProtobufUtils
    from src.utils.decrypt import AESUtils
    protoUtils = ProtobufUtils()
    aesUtils = AESUtils()
    PROTO_AVAILABLE = True
except ImportError as e:
    print(f"⚠️ Proto import error: {e}")
    PROTO_AVAILABLE = False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Flask app for web interface and API
app = Flask(__name__)

BASE_DIR = Path(__file__).parent
LOG_FILE = BASE_DIR / "access_token_log.txt"
FIREBASE_URL = "https://uid-bypass-findex-default-rtdb.asia-southeast1.firebasedatabase.app/users.json"

UID_CACHE = set()
CACHE_LOCK = threading.Lock()
LAST_REFRESH = 0
REFRESH_INTERVAL = 300

# Same constants as original
UNK_102_OB53 = bytes.fromhex("655c1616704a0b0f24515e165a13")
KEY = base64.b64decode("WWcmdGMlREV1aDYlWmNeOA==")
IV = base64.b64decode("Nm95WkRyMjJFM3ljaGpNJQ==")

# Same region profiles as original
REGION_PROFILES = {
    "IN": {
        "country": "IN", "language": "en",
        "carriers": ["40445", "40551", "40552", "40553"],
        "devices": ["SM-S918B", "CPH2581", "Pixel 8 Pro", "2211133G"],
        "network": "5G",
        "user_agent": "Dalvik/2.1.0 (Linux; U; Android 14; SM-S918B Build/UP1A.231005.007)"
    },
    "US": {
        "country": "US", "language": "en-US",
        "carriers": ["310260", "310410", "311480", "310150"],
        "devices": ["Pixel 8 Pro", "SM-S928B", "CPH2581", "SM-S918B"],
        "network": "5G",
        "user_agent": "Dalvik/2.1.0 (Linux; U; Android 14; Pixel 8 Pro Build/UP1A.231005.007)"
    },
    "BR": {
        "country": "BR", "language": "pt-BR",
        "carriers": ["72405", "72406", "72410", "72415"],
        "devices": ["SM-S918B", "M2007J20CG", "CPH2581", "2211133G"],
        "network": "4G",
        "user_agent": "Dalvik/2.1.0 (Linux; U; Android 14; SM-S918B Build/UP1A.231005.007)"
    },
    "SG": {
        "country": "SG", "language": "en-SG",
        "carriers": ["52501", "52502", "52503", "52505"],
        "devices": ["CPH2581", "SM-S918B", "Pixel 8 Pro", "2211133G"],
        "network": "5G",
        "user_agent": "Dalvik/2.1.0 (Linux; U; Android 14; CPH2581 Build/UP1A.231005.007)"
    },
    "EU": {
        "country": "GB", "language": "en-GB",
        "carriers": ["23410", "23415", "23420", "23430"],
        "devices": ["SM-S928B", "Pixel 8 Pro", "CPH2581", "SM-S918B"],
        "network": "5G",
        "user_agent": "Dalvik/2.1.0 (Linux; U; Android 14; SM-S928B Build/UP1A.231005.007)"
    },
    "DEFAULT": {
        "country": "IN", "language": "en",
        "carriers": ["40445"],
        "devices": ["SM-S918B"],
        "network": "5G",
        "user_agent": "Dalvik/2.1.0 (Linux; U; Android 14; SM-S918B Build/UP1A.231005.007)"
    }
}

ANDROID_VERSIONS = [
    "Android OS 15 / API-35 (TP1A.220905.001/U.R4T2.1c822c2_1_3)",
    "Android OS 14 / API-34 (UP1A.231005.007)",
    "Android OS 13 / API-33 (TQ3A.230805.001)",
]

def get_random_device(profile):
    return random.choice(profile["devices"])

def get_random_carrier(profile):
    return random.choice(profile["carriers"])

def get_random_android():
    return random.choice(ANDROID_VERSIONS)

def get_random_ram():
    return random.randint(6000, 12000)

def get_random_loading_time():
    return random.randint(15000, 35000)

def get_random_delay():
    return random.uniform(0.05, 0.3)

def get_random_oaid():
    return f"{uuid.uuid4().hex[:8]}-{uuid.uuid4().hex[:4]}-{uuid.uuid4().hex[:4]}-{uuid.uuid4().hex[:4]}-{uuid.uuid4().hex[:12]}"

def load_whitelist():
    global UID_CACHE, LAST_REFRESH
    new_uids = set()
    print("\n[🔥] Fetching UIDs from Firebase...")
    try:
        resp = requests.get(FIREBASE_URL, timeout=15)
        if resp.status_code == 200:
            users = resp.json()
            if users:
                count = 0
                for key, user_data in users.items():
                    uids = user_data.get("uids", {})
                    if isinstance(uids, dict):
                        for uid_key, uid_data in uids.items():
                            if isinstance(uid_data, dict) and "uid" in uid_data:
                                new_uids.add(str(uid_data["uid"]))
                                count += 1
                print(f"[✓] Total UIDs loaded from Firebase: {count}")
            else:
                print("[!] No data found in Firebase")
        else:
            print(f"[✗] Firebase error: HTTP {resp.status_code}")
    except Exception as e:
        print(f"[✗] Firebase connection error: {e}")
    
    with CACHE_LOCK:
        UID_CACHE = new_uids
        LAST_REFRESH = time.time()
    print(f"[✓] UID Cache Size: {len(UID_CACHE)} UIDs\n")

def check_uid(uid):
    uid = str(uid).strip()
    if uid == "0":
        return True
    with CACHE_LOCK:
        return uid in UID_CACHE

def build_majorlogin_ob53(open_id, access_token, platform_type, real_ip, profile, region):
    if not PROTO_AVAILABLE:
        return None
    
    pt = str(platform_type) if platform_type else "3"
    event_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    
    msg = MajorLoginOb53()
    msg.event_time = event_time
    msg.game_name = "free fire"
    msg.client_version = "1.123.6"
    msg.system_software = get_random_android()
    msg.system_hardware = "qcom"
    msg.telecom_operator = get_random_carrier(profile)
    msg.network_type = profile["network"]
    msg.screen_width = 2412
    msg.screen_height = 1080
    msg.screen_dpi = "480"
    msg.processor_details = "ARM64 FP ASIMD AES | 5260 | 8"
    msg.memory = get_random_ram()
    msg.gpu_renderer = "Adreno (TM) 740"
    msg.gpu_version = "OpenGL ES 3.2 V@0676.65"
    msg.unique_device_id = uuid.uuid4().hex
    msg.client_ip = real_ip
    msg.language = profile["language"]
    msg.open_id = open_id
    msg.open_id_type = pt
    msg.device_type = "Handheld"
    msg.device_model = get_random_device(profile)
    msg.country = profile["country"]
    msg.access_token = access_token
    msg.platform_sdk_id = 1
    msg.internal_storage_total = 256000
    msg.internal_storage_available = 128000
    msg.reg_avatar = 1
    msg.library_token = "AndroidDevice"
    msg.channel_type = 3
    msg.cpu_type = 1
    msg.client_version_code = "2019120273"
    msg.graphics_api = "OpenGL ES 3.2"
    msg.supported_astc_bitset = 255
    msg.login_open_id_type = 3
    msg.loading_time = get_random_loading_time()
    msg.release_channel = "android"
    msg.extra_info = "KqsHT7MUjyjjnA/jcWo74TjG04IMJoCAYFBIAOaqjgev7SOLjHCkzmg2MVIU4w9Hoxb4LQ=="
    msg.origin_platform_type = pt
    msg.primary_platform_type = pt
    msg.unk_102 = UNK_102_OB53
    msg.oaid = get_random_oaid()
    
    return msg.SerializeToString()

def extract_uid_from_response(content):
    """Extract UID from login response"""
    try:
        if PROTO_AVAILABLE and aesUtils:
            decrypted = aesUtils.decrypt_aes_cbc(content)
            major_res = MajorLoginResOb53()
            major_res.ParseFromString(decrypted)
            if major_res.account_uid:
                return str(major_res.account_uid)
    except:
        pass
    
    try:
        if PROTO_AVAILABLE:
            decoded = protoUtils.decode_protobuf(content, getUID)
            return str(decoded.uid)
    except:
        pass
    
    return None

# Flask Routes - Proxy endpoint
@app.route('/MajorLogin', methods=['POST', 'GET', 'PUT', 'DELETE', 'PATCH'])
@app.route('/majorlogin', methods=['POST', 'GET', 'PUT', 'DELETE', 'PATCH'])
@app.route('/proxy/majorlogin', methods=['POST'])
def handle_majorlogin():
    """Main proxy endpoint - mimics mitmproxy behavior"""
    try:
        # Log request
        print(f"[INTERCEPT] MajorLogin from {request.remote_addr}")
        
        # Get real IP
        real_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        
        # Get region profile
        auth_header = request.headers.get('Authorization', '')
        region = "DEFAULT"
        if auth_header:
            try:
                match = re.search(r"Bearer\s+([\w\-\.]+)", auth_header)
                if match:
                    token = match.group(1)
                    payload = token.split(".")[1]
                    payload += "=" * (4 - len(payload) % 4)
                    decoded = json.loads(base64.urlsafe_b64decode(payload))
                    region = decoded.get("lock_region", decoded.get("region", "DEFAULT"))
            except:
                pass
        
        profile = REGION_PROFILES.get(region, REGION_PROFILES["DEFAULT"])
        
        # Extract credentials from request body
        raw_body = request.get_data()
        
        # Parse LoginReq if possible
        open_id = None
        access_token = None
        pt = "3"
        
        # Try to parse as LoginReq (plain or encrypted)
        try:
            if len(raw_body) % 16 == 0:
                cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted = decryptor.update(raw_body) + decryptor.finalize()
                # Remove PKCS7 padding
                pad = decrypted[-1]
                if pad <= 16:
                    decrypted = decrypted[:-pad]
                login_req = LoginReq()
                login_req.ParseFromString(decrypted)
                if login_req.open_id:
                    open_id = login_req.open_id
                    access_token = login_req.login_token
                    pt = login_req.open_id_type or "3"
        except:
            pass
        
        # If not found, try direct protobuf
        if not open_id:
            try:
                login_req = LoginReq()
                login_req.ParseFromString(raw_body)
                if login_req.open_id:
                    open_id = login_req.open_id
                    access_token = login_req.login_token
                    pt = login_req.open_id_type or "3"
            except:
                pass
        
        if not open_id:
            return Response("Could not extract credentials", status=400)
        
        print(f"[OPEN_ID] {open_id}")
        print(f"[REGION] {region}")
        
        # Build new MajorLogin request
        plain = build_majorlogin_ob53(open_id, access_token, pt, real_ip, profile, region)
        if not plain:
            return Response("Proto not available", status=500)
        
        encrypted_body = aesUtils.encrypt_aes_cbc(plain)
        
        # Forward to real server
        headers = {
            "Accept": "*/*",
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/x-www-form-urlencoded",
            "Host": "loginbp.ggpolarbear.com",
            "ReleaseVersion": "OB53",
            "User-Agent": profile["user_agent"],
        }
        
        # Random delay to mimic human behavior
        time.sleep(get_random_delay())
        
        resp = requests.post(
            "https://loginbp.ggblueshark.com/MajorLogin",
            data=bytes.fromhex(encrypted_body.hex()),
            headers=headers,
            verify=False,
            timeout=20
        )
        
        # Extract and check UID
        uid = extract_uid_from_response(resp.content)
        
        if uid and not check_uid(uid):
            print(f"[✗ ACCESS DENIED] UID {uid}")
            error_msg = f"""ACCESS DENIED - UID {uid} not whitelisted
Contact: FINDEX CORPORATION"""
            return Response(error_msg, status=403, mimetype='text/plain')
        
        if uid:
            print(f"[✓ ACCESS GRANTED] UID {uid}")
        
        # Return response
        return Response(resp.content, status=resp.status_code, headers={
            'Content-Type': resp.headers.get('Content-Type', 'application/octet-stream')
        })
        
    except Exception as e:
        print(f"[ERROR] {e}")
        return Response(f"Proxy error: {str(e)}", status=500)

@app.route('/')
def home():
    return f"""
    <html>
    <head><title>FINDEX BYPASS - Railway Proxy</title></head>
    <body style="background:#000;color:#0f0;font-family:monospace;text-align:center;padding-top:50px;">
        <h1>🔥 FINDEX BYPASS PROXY RUNNING ON RAILWAY 🔥</h1>
        <p>Status: <span style="color:#0f0;">● ONLINE</span></p>
        <p>UIDs in Cache: <strong>{len(UID_CACHE)}</strong></p>
        <p>Proto Available: {'✅' if PROTO_AVAILABLE else '❌'}</p>
        <p>Proxy Endpoint: <code>POST /MajorLogin</code></p>
        <p>To use this proxy, send your requests to:</p>
        <code>https://your-app.railway.app/MajorLogin</code>
        <hr>
        <p><a href="/health" style="color:#0ff;">Health Check</a> | <a href="/stats" style="color:#0ff;">Stats</a></p>
    </body>
    </html>
    """

@app.route('/health')
def health():
    return {"status": "ok", "uids": len(UID_CACHE), "last_refresh": LAST_REFRESH, "proto": PROTO_AVAILABLE}

@app.route('/stats')
def stats():
    return {
        "total_uids": len(UID_CACHE),
        "refresh_interval": REFRESH_INTERVAL,
        "last_refresh": LAST_REFRESH,
        "sample_uids": list(UID_CACHE)[:10]
    }

# Load whitelist on startup
load_whitelist()

# Auto-refresh thread
def auto_refresh():
    while True:
        time.sleep(REFRESH_INTERVAL)
        load_whitelist()

threading.Thread(target=auto_refresh, daemon=True).start()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    print("\n" + "="*55)
    print(" 🔥 FINDEX BYPASS - RAILWAY PROXY MODE 🔥")
    print("="*55)
    print(f" ✅ Proxy Endpoint: /MajorLogin")
    print(f" ✅ UIDs Loaded: {len(UID_CACHE)}")
    print(f" ✅ Proto Available: {PROTO_AVAILABLE}")
    print(f" ✅ Port: {port}")
    print(f" ✅ URL: https://your-app.railway.app")
    print("="*55 + "\n")
    
    app.run(host='0.0.0.0', port=port, threaded=True)
