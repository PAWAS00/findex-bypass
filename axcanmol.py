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
from flask import Flask, request, jsonify
import requests
import urllib3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone

# Suppress warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Flask app
app = Flask(__name__)

BASE_DIR = Path(__file__).parent
LOG_FILE = BASE_DIR / "access_token_log.txt"
FIREBASE_URL = "https://uid-bypass-findex-default-rtdb.asia-southeast1.firebasedatabase.app/users.json"

# Import your proto modules (yeh tumhare paas already hoga)
from src.core.majorlogin_ob53_pb2 import MajorLoginOb53, MajorLoginResOb53
from src.core.login_pb2 import getUID, LoginReq
from src.utils.proto_utils import ProtobufUtils
from src.utils.decrypt import AESUtils

protoUtils = ProtobufUtils()
aesUtils = AESUtils()

UID_CACHE = set()
CACHE_LOCK = threading.Lock()
LAST_REFRESH = 0
REFRESH_INTERVAL = 300

# Your existing region profiles and helper functions (same as before)
UNK_102_OB53 = bytes.fromhex("655c1616704a0b0f24515e165a13")
KEY = base64.b64decode("WWcmdGMlREV1aDYlWmNeOA==")
IV = base64.b64decode("Nm95WkRyMjJFM3ljaGpNJQ==")

REGION_PROFILES = {
    "IN": {
        "country": "IN", "language": "en",
        "carriers": ["40445", "40551", "40552", "40553"],
        "devices": ["SM-S918B", "CPH2581", "Pixel 8 Pro"],
        "network": "5G",
        "user_agent": "Dalvik/2.1.0 (Linux; U; Android 14; SM-S918B Build/UP1A.231005.007)"
    },
    "US": {
        "country": "US", "language": "en-US",
        "carriers": ["310260", "310410"],
        "devices": ["Pixel 8 Pro", "SM-S928B"],
        "network": "5G",
        "user_agent": "Dalvik/2.1.0 (Linux; U; Android 14; Pixel 8 Pro Build/UP1A.231005.007)"
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
    "Android OS 15 / API-35",
    "Android OS 14 / API-34",
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
    
    print("[🔥] Fetching UIDs from Firebase...")
    try:
        resp = requests.get(FIREBASE_URL, timeout=15)
        if resp.status_code == 200:
            users = resp.json()
            if users:
                for key, user_data in users.items():
                    uids = user_data.get("uids", {})
                    if isinstance(uids, dict):
                        for uid_key, uid_data in uids.items():
                            if isinstance(uid_data, dict) and "uid" in uid_data:
                                new_uids.add(str(uid_data["uid"]))
                print(f"[✓] Loaded {len(new_uids)} UIDs from Firebase")
    except Exception as e:
        print(f"[✗] Firebase error: {e}")
    
    with CACHE_LOCK:
        UID_CACHE = new_uids
        LAST_REFRESH = time.time()

def check_uid(uid):
    uid = str(uid).strip()
    if uid == "0":
        return True
    with CACHE_LOCK:
        return uid in UID_CACHE

def build_majorlogin_ob53(open_id, access_token, platform_type, real_ip, profile, region):
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
    msg.memory = get_random_ram()
    msg.gpu_renderer = "Adreno (TM) 740"
    msg.unique_device_id = uuid.uuid4().hex
    msg.client_ip = real_ip
    msg.language = profile["language"]
    msg.open_id = open_id
    msg.open_id_type = pt
    msg.device_model = get_random_device(profile)
    msg.country = profile["country"]
    msg.access_token = access_token
    msg.loading_time = get_random_loading_time()
    msg.origin_platform_type = pt
    msg.primary_platform_type = pt
    msg.unk_102 = UNK_102_OB53
    msg.oaid = get_random_oaid()
    
    return msg.SerializeToString()

@app.route('/')
def home():
    return """
    <html>
    <head><title>FINDEX BYPASS API</title></head>
    <body style="background:#000;color:#0f0;font-family:monospace;text-align:center;padding-top:50px;">
        <h1>🔥 FINDEX BYPASS RUNNING ON RAILWAY 🔥</h1>
        <p>UIDs in cache: <strong>""" + str(len(UID_CACHE)) + """</strong></p>
        <p>API Endpoints:</p>
        <ul style="list-style:none;">
            <li>POST /api/login - Send login request</li>
            <li>GET /api/check/&lt;uid&gt; - Check UID status</li>
            <li>GET /health - Health check</li>
        </ul>
    </body>
    </html>
    """

@app.route('/health')
def health():
    return {"status": "ok", "uids": len(UID_CACHE), "last_refresh": LAST_REFRESH}

@app.route('/api/check/<uid>')
def check_uid_api(uid):
    """Check if UID is whitelisted"""
    is_valid = check_uid(uid)
    return jsonify({
        "uid": uid,
        "authorized": is_valid,
        "message": "GRANTED" if is_valid else "DENIED"
    })

@app.route('/api/login', methods=['POST'])
def handle_login():
    """Handle login request - Replace your proxy with this"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data"}), 400
        
        open_id = data.get('open_id')
        access_token = data.get('access_token')
        platform_type = data.get('platform_type', '3')
        
        if not open_id or not access_token:
            return jsonify({"error": "open_id and access_token required"}), 400
        
        # Get real IP
        real_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        profile = REGION_PROFILES["DEFAULT"]
        
        # Build and send request
        plain = build_majorlogin_ob53(open_id, access_token, platform_type, real_ip, profile, "DEFAULT")
        encrypted_body = aesUtils.encrypt_aes_cbc(plain)
        
        headers = {
            "Accept": "*/*",
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/x-www-form-urlencoded",
            "Host": "loginbp.ggpolarbear.com",
            "ReleaseVersion": "OB53",
            "User-Agent": profile["user_agent"],
        }
        
        resp = requests.post(
            "https://loginbp.ggblueshark.com/MajorLogin",
            data=bytes.fromhex(encrypted_body.hex()),
            headers=headers,
            verify=False,
            timeout=20
        )
        
        # Extract UID from response
        uid_extracted = None
        try:
            decrypted_resp = aesUtils.decrypt_aes_cbc(resp.content)
            major_res = MajorLoginResOb53()
            major_res.ParseFromString(decrypted_resp)
            if major_res.account_uid:
                uid_extracted = str(major_res.account_uid)
        except:
            pass
        
        # Check if UID is authorized
        if uid_extracted and check_uid(uid_extracted):
            return jsonify({
                "success": True,
                "uid": uid_extracted,
                "authorized": True,
                "message": "Access granted"
            })
        elif uid_extracted:
            return jsonify({
                "success": False,
                "uid": uid_extracted,
                "authorized": False,
                "message": "Access denied - UID not whitelisted"
            }), 403
        else:
            return jsonify({
                "success": resp.status_code == 200,
                "status_code": resp.status_code,
                "message": "Login processed but UID not extracted"
            })
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Background thread for refreshing UIDs
def auto_refresh():
    while True:
        time.sleep(REFRESH_INTERVAL)
        load_whitelist()

# Initial load
load_whitelist()
threading.Thread(target=auto_refresh, daemon=True).start()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    print(f"\n{'='*55}")
    print(" 🔥 FINDEX BYPASS - RAILWAY API SERVER 🔥")
    print(f"{'='*55}")
    print(f" ✅ Port: {port}")
    print(f" ✅ UIDs Loaded: {len(UID_CACHE)}")
    print(f" ✅ API: http://0.0.0.0:{port}/api/login")
    print(f"{'='*55}\n")
    app.run(host='0.0.0.0', port=port)
