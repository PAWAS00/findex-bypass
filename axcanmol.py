import sys
import os
import uuid
import threading
import time
import random
import base64
import binascii
import re
import json
from pathlib import Path
from flask import Flask, request, Response, send_file
import requests
import urllib3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone
import asyncio

# Railway specific - remove mitmproxy imports
# from mitmproxy import http
# from mitmproxy.tools.main import mitmdump

from src.core.majorlogin_ob53_pb2 import MajorLoginOb53, MajorLoginResOb53
from src.core.login_pb2 import getUID, LoginReq
from src.utils.proto_utils import ProtobufUtils
from src.utils.decrypt import AESUtils

if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_DIR = Path(__file__).parent
LOG_FILE = BASE_DIR / "access_token_log.txt"
FIREBASE_URL = "https://uid-bypass-findex-default-rtdb.asia-southeast1.firebasedatabase.app/users.json"

protoUtils = ProtobufUtils()
aesUtils = AESUtils()

UID_CACHE = set()
CACHE_LOCK = threading.Lock()
LAST_REFRESH = 0
REFRESH_INTERVAL = 300  # 5 minutes

# Flask app for Railway
app = Flask(__name__)

CERT_CONTENT = """-----BEGIN CERTIFICATE-----
MIIDNTCCAh2gAwIBAgIUBLR7NXSvUpUAI2PcRNeHfRpblNAwDQYJKoZIhvcNAQEL
BQAwKDESMBAGA1UEAwwJbWl0bXByb3h5MRIwEAYDVQQKDAltaXRtcHJveHkwHhcN
MjYwNTA4MjMwNDI5WhcNMzYwNTA3MjMwNDI5WjAoMRIwEAYDVQQDDAltaXRtcHJv
eHkxEjAQBgNVBAoMCW1pdG1wcm94eTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAKtVl9j1inTb9rAW5WpHYhomneHRei2eA+LXM990Kv6cjp54zM/HCXbC
AWp6BqVg0f8JF9zwcIDyqi1OLmgCqbb9TDBYNF8az2FWpKhyc+b9B8Dkj6kEX13M
qYN6se6G1QkXGyax6zkhwQaYzxttfa53tr909il4dZ/KxBVZ+WAuUkkcSGOwvT2x
R2ksPy7I41ZOoy5+MOeqcS1YlIVOFMzC7IPxDelsrWxfKf+KeIWkdX5vBF1yBtQ0
v0VdTdIaOqIAnyjpWZC4JQFybsi5FjmxpsVSM/rSsA2iMZKaArqYXHysi87przWf
rB2Ra3gwYZxA70fPNVOlTqXYyyQYhb8CAwEAAaNXMFUwDwYDVR0TAQH/BAUwAwEB
/zATBgNVHSUEDDAKBggrBgEFBQcDATAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYE
FAuSLwtgKo8FfbiYSDatrUXpyLEHMA0GCSqGSIb3DQEBCwUAA4IBAQAF6SZy7b59
5rhEXmBZr4E2t/JHJ12dJJTFQgey88E+q1bzjyqooH+vWl+1j2KRCVFDm9T4mhmC
2FIJ5rJ4Ad3+4MzUOXkmfHf0NAbK3G8Vpln+sTGAbvLdbjd7p2nJ9z6jV9OGM4mT
UnfRsxAtgj2mGrfsgPIG1TgFoPk+0HPJTBaq76bH6p2lRCgPwudRwsBWT0GX+J10
weqvEUGvKscIcTAdqEqauD4ftGuyncVyk056gG7RlsEgJUKWYWS8XtQxw2UiG2q1
0WEs5DoI+WQzLTf7NPNndHPDwAlZ8JjQmJacWmhAKAamwE4lo8/PnEK2AYNWS3ey
N1IEVDr7iQBY
-----END CERTIFICATE-----"""

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length"
}

UNK_102_OB53 = bytes.fromhex("655c1616704a0b0f24515e165a13")

# Region Profiles
REGION_PROFILES = {
    "IN": {
        "country": "IN",
        "language": "en",
        "carriers": ["40445", "40551", "40552", "40553"],
        "devices": ["SM-S918B", "CPH2581", "Pixel 8 Pro", "2211133G"],
        "network": "5G",
        "user_agent": "Dalvik/2.1.0 (Linux; U; Android 14; SM-S918B Build/UP1A.231005.007)"
    },
    "US": {
        "country": "US",
        "language": "en-US",
        "carriers": ["310260", "310410", "311480", "310150"],
        "devices": ["Pixel 8 Pro", "SM-S928B", "CPH2581", "SM-S918B"],
        "network": "5G",
        "user_agent": "Dalvik/2.1.0 (Linux; U; Android 14; Pixel 8 Pro Build/UP1A.231005.007)"
    },
    "BR": {
        "country": "BR",
        "language": "pt-BR",
        "carriers": ["72405", "72406", "72410", "72415"],
        "devices": ["SM-S918B", "M2007J20CG", "CPH2581", "2211133G"],
        "network": "4G",
        "user_agent": "Dalvik/2.1.0 (Linux; U; Android 14; SM-S918B Build/UP1A.231005.007)"
    },
    "SG": {
        "country": "SG",
        "language": "en-SG",
        "carriers": ["52501", "52502", "52503", "52505"],
        "devices": ["CPH2581", "SM-S918B", "Pixel 8 Pro", "2211133G"],
        "network": "5G",
        "user_agent": "Dalvik/2.1.0 (Linux; U; Android 14; CPH2581 Build/UP1A.231005.007)"
    },
    "EU": {
        "country": "GB",
        "language": "en-GB",
        "carriers": ["23410", "23415", "23420", "23430"],
        "devices": ["SM-S928B", "Pixel 8 Pro", "CPH2581", "SM-S918B"],
        "network": "5G",
        "user_agent": "Dalvik/2.1.0 (Linux; U; Android 14; SM-S928B Build/UP1A.231005.007)"
    },
    "DEFAULT": {
        "country": "IN",
        "language": "en",
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

def get_region_from_jwt(flow):
    try:
        auth_header = flow.request.headers.get("Authorization", "")
        if auth_header:
            match = re.search(r"Bearer\s+([\w\-\.]+)", auth_header)
            if match:
                token = match.group(1)
                payload = token.split(".")[1]
                payload += "=" * (4 - len(payload) % 4)
                decoded = json.loads(base64.urlsafe_b64decode(payload))
                region = decoded.get("lock_region", decoded.get("region", "DEFAULT"))
                if region in REGION_PROFILES:
                    return region
    except:
        pass
    return "DEFAULT"

def get_region_profile(flow):
    region = get_region_from_jwt(flow)
    return REGION_PROFILES.get(region, REGION_PROFILES["DEFAULT"]), region

def get_random_device(profile):
    return random.choice(profile["devices"])

def get_random_carrier(profile):
    return random.choice(profile["carriers"])

def get_random_android():
    return random.choice(ANDROID_VERSIONS)

def get_random_ram():
    return random.randint(6000, 12000)

def get_random_google_account():
    return f"Google|{uuid.uuid4().hex}"

def get_random_session_id():
    return uuid.uuid4().hex[:32]

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
                                uid_val = str(uid_data["uid"])
                                new_uids.add(uid_val)
                                count += 1
                                print(f"  ✓ {uid_val} (Client: {user_data.get('username', 'Unknown')})")
                
                print(f"\n[✓] Total UIDs loaded from Firebase: {count}")
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
        if time.time() - LAST_REFRESH > REFRESH_INTERVAL:
            threading.Thread(target=load_whitelist, daemon=True).start()
        return uid in UID_CACHE

def log_access_token(open_id, access_token, platform="", uid="", status=""):
    try:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        line = f"[{ts}] open_id={open_id} | token={access_token} | platform={platform}"
        if uid:
            line += f" | uid={uid}"
        if status:
            line += f" | status={status}"
        line += "\n"
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(line)
    except:
        pass

def build_majorlogin_ob53(open_id, access_token, platform_type, real_ip, profile, region):
    pt = str(platform_type) if platform_type else "3"
    event_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    
    session_device = get_random_device(profile)
    session_carrier = get_random_carrier(profile)
    session_android = get_random_android()
    session_ram = get_random_ram()
    session_google = get_random_google_account()
    session_id = get_random_session_id()
    loading_time = get_random_loading_time()
    oaid = get_random_oaid()
    
    msg = MajorLoginOb53()
    msg.event_time = event_time
    msg.game_name = "free fire"
    msg.client_version = "1.123.6"
    msg.system_software = session_android
    msg.system_hardware = "qcom"
    msg.telecom_operator = session_carrier
    msg.network_type = profile["network"]
    msg.screen_width = 2412
    msg.screen_height = 1080
    msg.screen_dpi = "480"
    msg.processor_details = "ARM64 FP ASIMD AES | 5260 | 8"
    msg.memory = session_ram
    msg.gpu_renderer = "Adreno (TM) 740"
    msg.gpu_version = "OpenGL ES 3.2 V@0676.65"
    msg.unique_device_id = uuid.uuid4().hex
    msg.client_ip = real_ip
    msg.language = profile["language"]
    msg.open_id = open_id
    msg.open_id_type = pt
    msg.device_type = "Handheld"
    msg.device_model = session_device
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
    msg.loading_time = loading_time
    msg.release_channel = "android"
    msg.extra_info = "KqsHT7MUjyjjnA/jcWo74TjG04IMJoCAYFBIAOaqjgev7SOLjHCkzmg2MVIU4w9Hoxb4LQ=="
    msg.origin_platform_type = pt
    msg.primary_platform_type = pt
    msg.unk_102 = UNK_102_OB53
    
    if hasattr(msg, 'oaid'):
        msg.oaid = oaid
    
    return msg.SerializeToString()

def ob53_request_headers(access_token, profile):
    return {
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": f"{profile['language']},{profile['language'].split('-')[0]};q=0.9",
        "Authorization": f"Bearer {access_token}",
        "Connection": "keep-alive",
        "Content-Type": "application/x-www-form-urlencoded",
        "Host": "loginbp.ggpolarbear.com",
        "ReleaseVersion": "OB53",
        "User-Agent": profile["user_agent"],
        "X-GA": "v1 1",
        "X-Unity-Version": "2022.3.47f1",
    }

KEY = base64.b64decode("WWcmdGMlREV1aDYlWmNeOA==")
IV = base64.b64decode("Nm95WkRyMjJFM3ljaGpNJQ==")

def _aes_cbc_decrypt_nopad(data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    return cipher.decryptor().update(data) + cipher.decryptor().finalize()

def _strip_pkcs7(data):
    pad = data[-1]
    if 1 <= pad <= 16 and data[-pad:] == bytes([pad]) * pad:
        return data[:-pad]
    return data

def _try_proto(data, proto_cls):
    msg = proto_cls()
    msg.ParseFromString(data)
    oid = getattr(msg, "open_id", "") or ""
    tok = getattr(msg, "access_token", "") or getattr(msg, "login_token", "") or ""
    otyp = getattr(msg, "open_id_type", "") or ""
    ptype = getattr(msg, "origin_platform_type", "") or ""
    if not ptype and otyp:
        ptype = otyp
    return oid, tok, otyp, ptype

def try_parse_loginreq_decrypted(raw_body):
    if len(raw_body) % 16 != 0:
        return None
    try:
        dec = _aes_cbc_decrypt_nopad(raw_body, KEY, IV)
        dec = _strip_pkcs7(dec)
        r = LoginReq()
        r.ParseFromString(dec)
        if r.open_id:
            return r
    except:
        pass
    return None

def try_parse_loginreq_plain(raw_body):
    try:
        r = LoginReq()
        r.ParseFromString(raw_body)
        if r.open_id:
            return r
    except:
        pass
    return None

def extract_credentials(raw_body):
    for proto_cls in (MajorLoginOb53, LoginReq):
        try:
            oid, tok, otyp, ptype = _try_proto(raw_body, proto_cls)
            if oid:
                print(f"[PARSE] Plain {proto_cls.__name__} OK — open_id={oid}")
                return oid, tok, otyp, ptype
        except:
            pass
    if len(raw_body) % 16 == 0:
        try:
            dec = _aes_cbc_decrypt_nopad(raw_body, KEY, IV)
            dec = _strip_pkcs7(dec)
            for proto_cls in (MajorLoginOb53, LoginReq):
                try:
                    oid, tok, otyp, ptype = _try_proto(dec, proto_cls)
                    if oid:
                        print(f"[PARSE] AES-CBC {proto_cls.__name__} OK — open_id={oid}")
                        return oid, tok, otyp, ptype
                except:
                    pass
        except:
            pass
    raise ValueError(f"Cannot parse MajorLogin body")

# Flask routes for Railway
@app.route('/cert')
def download_cert():
    return Response(CERT_CONTENT, mimetype='application/x-pem-file', headers={
        'Content-Disposition': 'attachment; filename=certificat_mitmproxy.pem'
    })

@app.route('/')
def home():
    return """
    <html>
    <head><title>FINDEX BYPASS</title></head>
    <body style="background:#000;color:#0f0;font-family:monospace;text-align:center;padding-top:50px;">
        <h1>🔥 FINDEX BYPASS IS ALIVE! 🔥</h1>
        <p>Proxy running on port 9944</p>
        <p><a href="/cert" style="color:#0ff;">📥 Download Certificate (certificat_mitmproxy.pem)</a></p>
        <p><a href="/health" style="color:#0ff;">Health Check</a></p>
    </body>
    </html>
    """

@app.route('/health')
def health():
    return {"status": "ok", "uid_cache": len(UID_CACHE), "last_refresh": LAST_REFRESH}

# Railway proxy endpoint - mimics mitmproxy
@app.route('/MajorLogin', methods=['POST'])
def handle_majorlogin():
    try:
        print(f"\n[INTERCEPT] MajorLogin")
        
        time.sleep(get_random_delay())
        
        real_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        
        # Create a mock flow object for region detection
        class MockFlow:
            class Request:
                headers = request.headers
            request = Request()
        
        profile, region = get_region_profile(MockFlow())
        
        print(f"[IP] Real client IP: {real_ip}")
        print(f"[REGION] Detected: {region}")
        
        raw = request.get_data()
        
        login_orig = try_parse_loginreq_plain(raw) or try_parse_loginreq_decrypted(raw)
        if login_orig:
            access_token = login_orig.login_token
            open_id = login_orig.open_id
            pt = login_orig.open_id_type or "3"
            print(f"[PARSE] LoginReq — open_id={open_id}")
        else:
            open_id, access_token, open_id_type, platform_type = extract_credentials(raw)
            pt = platform_type or open_id_type or "3"
            print(f"[PARSE] Fallback extract — open_id={open_id}")
        
        log_access_token(open_id, access_token, platform=pt)
        
        plain = build_majorlogin_ob53(open_id, access_token, pt, real_ip, profile, region)
        encrypted_body = aesUtils.encrypt_aes_cbc(plain)
        hdrs = ob53_request_headers(access_token, profile)
        
        time.sleep(get_random_delay())
        
        resp = requests.post(
            "https://loginbp.ggblueshark.com/MajorLogin",
            data=bytes.fromhex(encrypted_body.hex()),
            headers=hdrs,
            verify=False,
            timeout=20
        )
        
        if resp.status_code == 200:
            print(f"[BYPASS] OK")
        else:
            print(f"[BYPASS] HTTP {resp.status_code}")
        
        # Extract and check UID from response
        uid_str = None
        try:
            decrypted_resp = aesUtils.decrypt_aes_cbc(resp.content)
            major_res = MajorLoginResOb53()
            major_res.ParseFromString(decrypted_resp)
            if major_res.account_uid:
                uid_str = str(major_res.account_uid)
        except:
            pass
        
        if not uid_str:
            try:
                decoded = protoUtils.decode_protobuf(resp.content, getUID)
                uid_str = str(decoded.uid)
            except:
                pass
        
        if uid_str and uid_str != "0":
            print(f"[CHECK] UID: {uid_str}")
            
            if check_uid(uid_str):
                print(f"[✓ ACCESS GRANTED] UID {uid_str}")
                log_access_token("", "", "", uid_str, "GRANTED")
            else:
                print(f"[✗ ACCESS DENIED] UID {uid_str}")
                log_access_token("", "", "", uid_str, "DENIED")
                
                error_msg = f"""ACCESS DENIED - UID {uid_str} not whitelisted
Contact: FINDEX CORPORATION"""
                return Response(error_msg, status=403, mimetype='text/plain')
        
        return Response(resp.content, status=resp.status_code, headers={
            'Content-Type': resp.headers.get('Content-Type', 'application/octet-stream')
        })
                
    except Exception as e:
        print(f"[ERROR] {e}")
        return Response(f"Proxy error: {str(e)}", status=500)

# Initial load from Firebase
load_whitelist()

# Background auto-refresh thread
def auto_refresh():
    while True:
        time.sleep(REFRESH_INTERVAL)
        print("\n[🔄] Auto-refreshing UID cache...")
        load_whitelist()

refresh_thread = threading.Thread(target=auto_refresh, daemon=True)
refresh_thread.start()

if __name__ == "__main__":
    PORT = 9944
    
    print("\n" + "="*55)
    print(" 🔥 FINDEX BYPASS - RAILWAY DEPLOYED 🔥")
    print("="*55)
    print(f" ✅ Firebase URL: {FIREBASE_URL}")
    print(f" ✅ Auto-refresh: Every {REFRESH_INTERVAL}s")
    print(f" ✅ UID Cache: {len(UID_CACHE)} UIDs")
    print(f" ✅ Regions: IN, US, BR, SG, EU (Auto-detect)")
    print(f" ✅ Device: Region-specific random")
    print(f" ✅ Carrier: Region-specific random")
    print(f" ✅ RAM: Random range (6-12GB)")
    print(f" ✅ IP: REAL (No spoofing)")
    print(f" ✅ OAID: Random per session (OB53)")
    print(f" ✅ Timing: Randomized (Human-like)")
    print(f" ✅ Proxy: http://0.0.0.0:{PORT}")
    print(f" ✅ Cert Download: https://your-app.railway.app/cert")
    print("="*55 + "\n")
    
    app.run(host='0.0.0.0', port=PORT, threaded=True)
