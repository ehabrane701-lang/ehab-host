#!/usr/bin/env python3
"""
𝗘𝗛𝗔𝗕 𝐇𝐎𝐒𝐓 - نظام استضافة متطور مع لوحة تحكم وإدارة وبوت تيليجرام مدمج
طُوِّر بواسطة: 𝗘𝗛𝗔𝗕𝗔𝗜𝗛𝗔𝗪𝗕𝗔𝗡𝗜 | @Y_20_20
[محدث ومصحح بالكامل لضمان تشغيل ملفات بايثون وجافا سكريبت بكفاءة]
"""

import os
import json
import re
import subprocess
import psutil
import socket
import sys
import hashlib
import secrets
import time
import threading
import requests
import shutil
import zipfile
import signal
import logging
import base64
from datetime import datetime, timedelta
from flask import Flask, send_from_directory, request, jsonify, session, redirect, make_response

# مكتبات التشفير للحماية المتقدمة
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# مكتبات تيليجرام
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler,
    MessageHandler, filters, ContextTypes, ConversationHandler
)

# إعدادات التسجيل (Logging)
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_DIR = os.path.join(BASE_DIR, "USERS")
os.makedirs(USERS_DIR, exist_ok=True)

# مسارات التخزين الإضافية المطلوبة بنظام الحماية والهيكلة
RUNNING_DIR = os.path.join(BASE_DIR, "active_bots")
LOGS_DIR = os.path.join(BASE_DIR, "bot_logs")
DB_DIR = os.path.join(BASE_DIR, "database")
ASSETS_DIR = os.path.join(BASE_DIR, "assets")
STORE_DIR = os.path.join(BASE_DIR, "store_files")
THUMBS_DIR = os.path.join(ASSETS_DIR, "thumbs")
MARKET_DIR = os.path.join(BASE_DIR, "market")
ENV_DIR = os.path.join(BASE_DIR, "bot_environments")
ENCRYPTED_DIR = os.path.join(BASE_DIR, "encrypted_files")

for d in [RUNNING_DIR, LOGS_DIR, DB_DIR, ASSETS_DIR, STORE_DIR, THUMBS_DIR, MARKET_DIR, ENV_DIR, ENCRYPTED_DIR]:
    if not os.path.exists(d):
        os.makedirs(d)

USERS_DB = os.path.join(DB_DIR, "users.json")
FILES_DB = os.path.join(DB_DIR, "files.json")
SETTINGS_DB = os.path.join(DB_DIR, "settings.json")
STORE_DB = os.path.join(DB_DIR, "store.json")
ADMINS_DB = os.path.join(DB_DIR, "admins.json")
MARKET_DB = os.path.join(DB_DIR, "market.json")
SECURITY_DB = os.path.join(DB_DIR, "security.json")

db_lock = threading.Lock()
cancel_states = {}
last_bot_messages = {}
active_processes = {}
process_hours = {}
user_notifications = {}
admin_steps = {}

def read_json(path):
    with db_lock:
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            return {}
        except:
            return {}

def write_json(path, data):
    with db_lock:
        try:
            temp_path = path + ".tmp"
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=4)
            os.replace(temp_path, path)
        except Exception as e:
            print(f"JSON write error: {e}")

# نظام الحماية المتقدم للأكواد ضد الاختراق والتخريب
def scan_code_security(content):
    dangerous_patterns = [
        r"\bos\.system\s*\(",
        r"\bos\.popen\s*\(",
        r"\bshutil\.rmtree\s*\(\s*[\"\"]\/",
        r"\bctypes\b",
        r"open\s*\(\s*[\"\"].*\/etc\/passwd",
        r"open\s*\(\s*[\"\"].*\/root\/",
        r"rm\s+-rf\s+/",
        r"\bsubprocess\.Popen\s*\(\s*\[\s*[\"\"]rm",
        r"\beval\s*\(",
        r"\bexec\s*\("
    ]
    for pattern in dangerous_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            return False, "⚠️ تم رفض الملف حظراً أمنياً لاحتوائه على أكواد خطيرة أو محاولات اختراق."
    return True, "الكود آمن"

def init_security():
    security = read_json(SECURITY_DB)
    if "master_key" not in security:
        m_key = base64.b64encode(get_random_bytes(32)).decode("utf-8")
        security["master_key"] = m_key
        security["file_keys"] = {}
        write_json(SECURITY_DB, security)

def get_master_key():
    security = read_json(SECURITY_DB)
    master_key = security.get("master_key")
    if not master_key:
        master_key = base64.b64encode(get_random_bytes(32)).decode("utf-8")
        security["master_key"] = master_key
        write_json(SECURITY_DB, security)
    return base64.b64decode(master_key)

def generate_file_key(fid, user_id, admin_id, token):
    security = read_json(SECURITY_DB)
    file_keys = security.get("file_keys", {})
    if fid not in file_keys:
        combined = f"{fid}:{user_id}:{admin_id}:{token}"
        salt = hashlib.sha256(combined.encode()).digest()[:16]
        master_key = get_master_key()
        kdf = hashlib.pbkdf2_hmac("sha256", master_key, salt, 100000, dklen=32)
        file_keys[fid] = {
            "key": base64.b64encode(kdf).decode("utf-8"),
            "salt": base64.b64encode(salt).decode("utf-8"),
            "user_id": user_id
        }
        security["file_keys"] = file_keys
        write_json(SECURITY_DB, security)
    return file_keys[fid]

def get_file_key(fid):
    security = read_json(SECURITY_DB)
    file_keys = security.get("file_keys", {})
    return file_keys.get(fid)

def encrypt_file_content(content, fid, user_id, admin_id, token):
    try:
        file_key_info = generate_file_key(fid, user_id, admin_id, token)
        key = base64.b64decode(file_key_info["key"])
        salt = base64.b64decode(file_key_info["salt"])
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(content.encode("utf-8"), AES.block_size))
        encrypted_data = {
            "iv": base64.b64encode(cipher.iv).decode("utf-8"),
            "ciphertext": base64.b64encode(ct_bytes).decode("utf-8"),
            "salt": base64.b64encode(salt).decode("utf-8"),
            "fid": fid,
            "user_id": user_id,
            "timestamp": datetime.now().isoformat()
        }
        return json.dumps(encrypted_data)
    except Exception as e:
        print(f"Encryption error: {e}")
        return None

def decrypt_file_content(encrypted_json, fid):
    try:
        data = json.loads(encrypted_json)
        file_key_info = get_file_key(fid)
        if not file_key_info:
            return None
        key = base64.b64decode(file_key_info["key"])
        iv = base64.b64decode(data["iv"])
        ct = base64.b64decode(data["ciphertext"])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode("utf-8")
    except Exception as e:
        print(f"Decryption error: {e}")
        return None

def save_encrypted_file(fid, content, user_id, admin_id, token):
    encrypted_content = encrypt_file_content(content, fid, user_id, admin_id, token)
    if encrypted_content:
        encrypted_path = os.path.join(ENCRYPTED_DIR, f"{fid}.enc")
        with open(encrypted_path, "w", encoding="utf-8") as f:
            f.write(encrypted_content)
        return True
    return False

def load_encrypted_file(fid):
    encrypted_path = os.path.join(ENCRYPTED_DIR, f"{fid}.enc")
    if os.path.exists(encrypted_path):
        with open(encrypted_path, "r", encoding="utf-8") as f:
            encrypted_content = f.read()
        return decrypt_file_content(encrypted_content, fid)
    return None

def auto_fix_errors(code):
    fixes = [
        (r"\bprint\s+(\S+)", r"print(\1)"),
        (r"\praw_input\b", "input"),
        (r"\bxrange\b", "range"),
        (r"\.iteritems\(\)", ".items()"),
        (r"\.itervalues\(\)", ".values()"),
        (r"\.iterkeys\(\)", ".keys()"),
    ]
    for pattern, replacement in fixes:
        code = re.sub(pattern, replacement, code)
    return code

app = Flask(__name__, static_folder=BASE_DIR)
app.secret_key = "ZIAD_HOST_GOLD_2026_SUPER_SECRET_KEY"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

BOT_TOKEN = "9294301891:AAG4oWwRlxxnyCIe3yIutxr_NSELsgBic68"
ADMIN_TELEGRAM_IDS = [1002670694]
ADMIN_ID = 1002670694
API_BASE_URL = os.environ.get("API_BASE_URL", "https://ehab-10.onrender.com")

DEVELOPER_INFO = "🛠 طُوِّر بواسطة: *𝗘𝗛𝗔𝗕𝗔𝗜𝗛𝗔𝗪𝗕𝗔𝗡𝗜*\n📬 تواصل: @Y_20_20"

def notify_admin(message: str):
    try:
        for admin_id in ADMIN_TELEGRAM_IDS:
            requests.post(
                f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
                json={"chat_id": admin_id, "text": message, "parse_mode": "Markdown"},
                timeout=3
            )
    except Exception:
        pass

# قراءة محتوى ملفات HTML تلقائياً
def load_html(filename):
    path = os.path.join(BASE_DIR, filename)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    return ""

LANDING_HTML_CONTENT = load_html("landing.html")
LOGIN_HTML_CONTENT = load_html("login.html")
INDEX_HTML_CONTENT = load_html("index.html")
ADMIN_HTML_CONTENT = load_html("admin_panel.html")

DB_FILE = os.path.join(BASE_DIR, "db.json")

def load_db():
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if "plans" not in data:
                    data["plans"] = {}
                if "server_types" not in data:
                    data["server_types"] = ["Python", "Node.js"]
                if "pending_users" not in data:
                    data["pending_users"] = []
                return data
        except Exception:
            pass
    
    admin_email = os.environ.get("ADMIN_EMAIL", "ehab776771@gmail.com")
    admin_password = os.environ.get("ADMIN_PASSWORD", "Y_20_20")
    admin_hash = hashlib.sha256(admin_password.encode()).hexdigest()
    
    default_db = {
        "users": {
            admin_email: {
                "password": admin_hash,
                "is_admin": True,
                "created_at": str(datetime.now()),
                "max_servers": 999999,
                "expiry_days": 3650,
                "last_login": None,
                "telegram_id": ADMIN_TELEGRAM_IDS[0],
                "api_key": None,
                "storage_limit": 10240,
                "plan": "admin"
            }
        },
        "servers": {},
        "logs": [],
        "pending_users": [],
        "plans": {
            "free": {"name": "🎁 مجاني", "storage": 512000, "ram": 256, "cpu": 0.5, "max_servers": 2, "price": 0},
            "4gb": {"name": "💎 4 جيجا", "storage": 4096000, "ram": 1024, "cpu": 1, "max_servers": 5, "price": 5},
            "10gb": {"name": "💎 10 جيجا", "storage": 10240000, "ram": 2048, "cpu": 2, "max_servers": 10, "price": 10}
        },
        "server_types": ["Python", "Node.js"]
    }
    save_db(default_db)
    return default_db

def save_db(db_data):
    try:
        with open(DB_FILE, "w", encoding="utf-8") as f:
            json.dump(db_data, f, indent=4, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"❌ خطأ في حفظ DB: {e}")
        return False

db = load_db()

PORT_RANGE_START = 8100
PORT_RANGE_END = 9100

def get_assigned_port():
    used = set()
    for srv in db.get("servers", {}).values():
        if srv.get("port"):
            used.add(srv["port"])
    for port in range(PORT_RANGE_START, PORT_RANGE_END):
        if port not in used:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.1)
                result = s.connect_ex(("127.0.0.1", port))
                s.close()
                if result != 0:
                    return port
            except Exception:
                return port
    return PORT_RANGE_START

def get_current_user():
    if "email" in session:
        return db["users"].get(session["email"])
    return None

def get_user_servers_dir(email):
    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    path = os.path.join(USERS_DIR, safe_email, "SERVERS")
    os.makedirs(path, exist_ok=True)
    return path

def is_admin(email):
    u = db["users"].get(email)
    return u.get("is_admin", False) if u else False

def generate_api_key():
    return secrets.token_urlsafe(32)

def get_user_by_api_key(api_key):
    for email, udata in db["users"].items():
        if udata.get("api_key") == api_key:
            return email, udata
    return None, None

def uptime_str(start_time):
    if not start_time:
        return "0 ثانية"
    diff = time.time() - start_time
    days = int(diff // 86400)
    hours = int((diff % 86400) // 3600)
    mins = int((diff % 3600) // 60)
    parts = []
    if days > 0: parts.append(f"{days} يوم")
    if hours > 0: parts.append(f"{hours} ساعة")
    if mins > 0: parts.append(f"{mins} دقيقة")
    return " و ".join(parts) if parts else "أقل من دقيقة"

def _check_admin_access():
    if "email" in session and is_admin(session["email"]):
        return True
    api_key = None
    if request.is_json:
        try:
            api_key = request.get_json().get("api_key")
        except Exception:
            pass
    if not api_key:
        api_key = request.args.get("api_key")
    if api_key:
        email, user = get_user_by_api_key(api_key)
        if email and is_admin(email):
            return True
    return False

def detect_main_file(srv_path: str) -> str:
    for candidate in ["main.py", "bot.py", "app.py", "index.py", "run.py", "start.py"]:
        if os.path.exists(os.path.join(srv_path, candidate)):
            return candidate
    py_files = [f for f in os.listdir(srv_path) if f.endswith(".py")]
    return py_files[0] if py_files else ""

def auto_install_deps(srv_path: str, log_file):
    try:
        req = os.path.join(srv_path, "requirements.txt")
        if os.path.exists(req):
            log_file.write(f"\n📦 تثبيت requirements.txt...\n")
            log_file.flush()
            proc = subprocess.Popen(
                [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"],
                cwd=srv_path, stdout=log_file, stderr=subprocess.STDOUT, env=os.environ.copy()
            )
            proc.wait(timeout=180)
            log_file.write("✅ تم تثبيت المكتبات بنجاح\n")
    except Exception as e:
        log_file.write(f"\n⚠️ تثبيت تلقائي: {e}\n")
    finally:
        try:
            log_file.close()
        except:
            pass

def detect_node_main_file(srv_path: str) -> str:
    candidates = ["index.js", "server.js", "app.js", "main.js", "bot.js", "start.js"]
    for candidate in candidates:
        if os.path.exists(os.path.join(srv_path, candidate)):
            return candidate
    js_files = [f for f in os.listdir(srv_path) if f.endswith(".js")]
    return js_files[0] if js_files else ""

def auto_install_node_deps(srv_path: str, log_file):
    try:
        package_json = os.path.join(srv_path, "package.json")
        if os.path.exists(package_json):
            log_file.write(f"\n📦 تثبيت حزم Node.js...\n")
            log_file.flush()
            proc = subprocess.Popen(
                ["npm", "install"], cwd=srv_path, stdout=log_file, stderr=subprocess.STDOUT, env=os.environ.copy()
            )
            proc.wait(timeout=180)
            log_file.write("✅ تم تثبيت حزم Node.js بنجاح\n")
    except Exception as e:
        log_file.write(f"\n⚠️ تثبيت حزم Node.js فشل (تأكد من توفر بيئة Node/NPM): {e}\n")
    finally:
        try:
            log_file.close()
        except:
            pass

def start_server_process(folder):
    srv = db["servers"].get(folder)
    if not srv:
        return False, "السيرفر غير موجود"
    if srv.get("server_type") == "Node.js":
        return start_node_server_process(folder)
    else:
        return start_python_server_process(folder)

def start_python_server_process(folder):
    srv = db["servers"].get(folder)
    if not srv:
        return False, "السيرفر غير موجود"
    
    main_file = srv.get("startup_file", "")
    if not main_file or not os.path.exists(os.path.join(srv["path"], main_file)):
        detected = detect_main_file(srv["path"])
        if detected:
            srv["startup_file"] = detected
            main_file = detected
            save_db(db)
        else:
            return False, "لا يوجد ملف تشغيل Python (.py)"

    file_path = os.path.join(srv["path"], main_file)
    if not os.path.exists(file_path):
        return False, f"الملف {main_file} غير موجود"

    port = srv.get("port") or get_assigned_port()
    srv["port"] = port
    save_db(db)

    log_path = os.path.join(srv["path"], "out.log")
    error_path = os.path.join(srv["path"], "errors.log")
    log_file = open(log_path, "a", encoding="utf-8")
    log_file.write(f"\n{'='*50}\n🚀 بدء التشغيل (Python) - {datetime.now()}\n📁 {main_file}\n🔌 المنفذ: {port}\n{'='*50}\n\n")
    log_file.flush()

    try:
        env = os.environ.copy()
        env["PORT"] = str(port)
        env["SERVER_PORT"] = str(port)
        cmd = [sys.executable, "-u", main_file]
        proc = subprocess.Popen(
            cmd, cwd=srv["path"], stdout=log_file, stderr=open(error_path, "a", encoding="utf-8"),
            env=env, preexec_fn=os.setsid if hasattr(os, 'setsid') else None
        )
        srv["status"] = "Running"
        srv["pid"] = proc.pid
        srv["start_time"] = time.time()
        save_db(db)
        return True, "✅ تم التشغيل بنجاح"
    except Exception as e:
        log_file.write(f"\n❌ خطأ: {e}\n")
        log_file.close()
        return False, str(e)

def start_node_server_process(folder):
    srv = db["servers"].get(folder)
    if not srv:
        return False, "السيرفر غير موجود"
    
    main_file = srv.get("startup_file", "")
    if not main_file or not os.path.exists(os.path.join(srv["path"], main_file)):
        detected = detect_node_main_file(srv["path"])
        if detected:
            srv["startup_file"] = detected
            main_file = detected
            save_db(db)
        else:
            return False, "لا يوجد ملف تشغيل JavaScript (.js)"

    file_path = os.path.join(srv["path"], main_file)
    if not os.path.exists(file_path):
        return False, f"الملف {main_file} غير موجود"

    port = srv.get("port") or get_assigned_port()
    srv["port"] = port
    save_db(db)

    log_path = os.path.join(srv["path"], "out.log")
    error_path = os.path.join(srv["path"], "errors.log")
    log_file = open(log_path, "a", encoding="utf-8")
    log_file.write(f"\n{'='*50}\n🚀 بدء التشغيل (Node.js) - {datetime.now()}\n📁 {main_file}\n🔌 المنفذ: {port}\n{'='*50}\n\n")
    log_file.flush()

    try:
        env = os.environ.copy()
        env["PORT"] = str(port)
        env["SERVER_PORT"] = str(port)
        cmd = ["node", main_file]
        proc = subprocess.Popen(
            cmd, cwd=srv["path"], stdout=log_file, stderr=open(error_path, "a", encoding="utf-8"),
            env=env, preexec_fn=os.setsid if hasattr(os, 'setsid') else None
        )
        srv["status"] = "Running"
        srv["pid"] = proc.pid
        srv["start_time"] = time.time()
        save_db(db)
        return True, "✅ تم التشغيل بنجاح"
    except Exception as e:
        log_file.write(f"\n❌ خطأ: {e}\n")
        log_file.close()
        return False, str(e)

def stop_server_process(folder):
    srv = db["servers"].get(folder)
    if not srv:
        return
    if srv.get("pid"):
        try:
            p = psutil.Process(srv["pid"])
            if hasattr(os, 'killpg'):
                try:
                    os.killpg(os.getpgid(p.pid), signal.SIGTERM)
                except Exception:
                    pass
            for child in p.children(recursive=True):
                child.kill()
            p.kill()
        except Exception:
            pass
    srv["status"] = "Stopped"
    srv["pid"] = None
    save_db(db)

def restart_server(folder):
    stop_server_process(folder)
    time.sleep(2)
    start_server_process(folder)

def process_monitor():
    while True:
        try:
            for folder, srv in list(db["servers"].items()):
                if srv.get("status") == "Running" and srv.get("pid"):
                    try:
                        p = psutil.Process(srv["pid"])
                        if not p.is_running() or p.status() == psutil.STATUS_ZOMBIE:
                            restart_server(folder)
                    except psutil.NoSuchProcess:
                        restart_server(folder)
                    except Exception:
                        pass
        except Exception:
            pass
        time.sleep(15)

threading.Thread(target=process_monitor, daemon=True).start()

@app.route('/')
def home():
    if 'email' in session:
        if is_admin(session['email']):
            return redirect('/admin')
        return redirect('/dashboard')
    return send_from_directory(BASE_DIR, "landing.html")

@app.route('/login')
def login_page():
    if 'email' in session:
        return redirect('/')
    return send_from_directory(BASE_DIR, "login.html")

@app.route('/dashboard')
def dashboard():
    if 'email' not in session:
        return redirect('/login')
    return send_from_directory(BASE_DIR, "index.html")

@app.route('/admin')
def admin_panel():
    if 'email' not in session or not is_admin(session['email']):
        return redirect('/login')
    return send_from_directory(BASE_DIR, "admin_panel.html")

@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "").strip()
    
    if not email or not password:
        return jsonify({"success": False, "message": "جميع الحقول مطلوبة"})
    if '@' not in email or '.' not in email:
        return jsonify({"success": False, "message": "البريد الإلكتروني غير صالح"})
    if len(password) < 4:
        return jsonify({"success": False, "message": "كلمة المرور 4 أحرف على الأقل"})
    if email in db["users"]:
        return jsonify({"success": False, "message": "البريد الإلكتروني موجود بالفعل"})

    db["users"][email] = {
        "password": hashlib.sha256(password.encode()).hexdigest(),
        "is_admin": False,
        "created_at": str(datetime.now()),
        "max_servers": db["plans"]["free"]["max_servers"],
        "expiry_days": 365,
        "last_login": None,
        "telegram_id": None,
        "api_key": None,
        "storage_limit": db["plans"]["free"]["storage"],
        "plan": "free"
    }
    save_db(db)
    
    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    user_dir = os.path.join(USERS_DIR, safe_email)
    os.makedirs(user_dir, exist_ok=True)
    os.makedirs(os.path.join(user_dir, "SERVERS"), exist_ok=True)

    threading.Thread(target=notify_admin, args=(f"🔔 *مستخدم جديد!*\n📧 {email}",), daemon=True).start()
    return jsonify({"success": True, "message": "✅ تم إنشاء حسابك بنجاح!"})

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "").strip()

    user = db["users"].get(email)
    if user and user["password"] == hashlib.sha256(password.encode()).hexdigest():
        session.clear()
        session['email'] = email
        session.permanent = True
        user["last_login"] = str(datetime.now())
        save_db(db)
        is_adm = user.get("is_admin", False)
        return jsonify({"success": True, "redirect": "/admin" if is_adm else "/dashboard", "is_admin": is_adm})

    return jsonify({"success": False, "message": "بيانات غير صحيحة"})

@app.route('/api/logout', methods=['GET', 'POST'])
def api_logout():
    session.clear()
    return jsonify({"success": True})

@app.route('/api/current_user')
def api_current_user():
    if 'email' in session:
        u = db["users"].get(session['email'])
        if u:
            return jsonify({
                "success": True,
                "email": session['email'],
                "username": session['email'],
                "is_admin": u.get("is_admin", False),
                "plan": u.get("plan", "free"),
                "api_key": u.get("api_key")
            })
    return jsonify({"success": False})

@app.route('/api/create_api_key', methods=['POST'])
def create_api_key_route():
    if 'email' not in session:
        return jsonify({"success": False, "message": "غير مصرح"}), 401
    email = session['email']
    new_key = generate_api_key()
    db["users"][email]["api_key"] = new_key
    save_db(db)
    return jsonify({"success": True, "api_key": new_key})

@app.route('/api/plans')
def get_plans():
    return jsonify({"success": True, "plans": db.get("plans", {})})

@app.route('/api/admin/users')
def admin_users():
    if not _check_admin_access():
        return jsonify({"success": False}), 403
    users_list = []
    for uemail, udata in db["users"].items():
        users_list.append({
            "email": uemail,
            "username": uemail,
            "is_admin": udata.get("is_admin", False),
            "created_at": udata.get("created_at"),
            "max_servers": udata.get("max_servers", 1),
            "expiry_days": udata.get("expiry_days", 365),
            "plan": udata.get("plan", "free")
        })
    return jsonify({"success": True, "users": users_list})

@app.route('/api/admin/create-user', methods=['POST'])
def admin_create_user():
    if not _check_admin_access():
        return jsonify({"success": False}), 403
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "").strip()
    max_servers = int(data.get("max_servers", 2))
    expiry_days = int(data.get("expiry_days", 365))
    
    if not email or not password:
        return jsonify({"success": False, "message": "البريد وكلمة المرور مطلوبة"})
    if email in db["users"]:
        return jsonify({"success": False, "message": "المستخدم موجود بالفعل"})
    
    db["users"][email] = {
        "password": hashlib.sha256(password.encode()).hexdigest(),
        "is_admin": False,
        "created_at": str(datetime.now()),
        "max_servers": max_servers,
        "expiry_days": expiry_days,
        "last_login": None,
        "telegram_id": None,
        "api_key": None,
        "storage_limit": db["plans"]["free"]["storage"],
        "plan": "free"
    }
    save_db(db)
    
    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    user_dir = os.path.join(USERS_DIR, safe_email)
    os.makedirs(user_dir, exist_ok=True)
    os.makedirs(os.path.join(user_dir, "SERVERS"), exist_ok=True)
    
    return jsonify({"success": True, "message": "✅ تم إنشاء الحساب بنجاح"})

@app.route('/api/admin/delete-user', methods=['POST'])
def admin_delete_user():
    if not _check_admin_access():
        return jsonify({"success": False}), 403
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    
    target_user = db["users"].get(email)
    if target_user and target_user.get("is_admin", False):
        return jsonify({"success": False, "message": "لا يمكن حذف الأدمن"})
    
    if email in db["users"]:
        for fid, srv in list(db["servers"].items()):
            if srv["owner"] == email:
                stop_server_process(fid)
                if os.path.exists(srv["path"]):
                    shutil.rmtree(srv["path"], ignore_errors=True)
                del db["servers"][fid]
        
        del db["users"][email]
        save_db(db)
        return jsonify({"success": True, "message": "🗑 تم حذف المستخدم"})
    return jsonify({"success": False, "message": "المستخدم غير موجود"})

@app.route('/api/admin/add-plan', methods=['POST'])
def admin_add_plan():
    if not _check_admin_access():
        return jsonify({"success": False}), 403
    data = request.get_json() or {}
    plan_id = data.get("plan_id", "").strip().lower()
    name = data.get("name", "").strip()
    if not plan_id or not name:
        return jsonify({"success": False, "message": "معرف الخطة والاسم مطلوبان"})
    
    db["plans"][plan_id] = {
        "name": name,
        "price": float(data.get("price", 0)),
        "storage": int(data.get("storage", 512000)),
        "ram": int(data.get("ram", 256)),
        "cpu": float(data.get("cpu", 0.5)),
        "max_servers": int(data.get("max_servers", 2))
    }
    save_db(db)
    return jsonify({"success": True, "message": "✅ تم إضافة الخطة بنجاح"})

@app.route('/api/system/metrics')
def get_metrics():
    return jsonify({
        "cpu": psutil.cpu_percent(),
        "memory": psutil.virtual_memory().percent,
        "disk": psutil.disk_usage('/').percent
    })

@app.route('/api/servers')
def list_servers():
    if 'email' not in session and not _check_admin_access():
        return jsonify({"success": False}), 401
    
    target_user = request.args.get("user")
    if target_user and is_admin(session.get('email', '')):
        owner_email = target_user
    else:
        owner_email = session.get('email')

    user_servers = []
    total_disk_used_mb = 0.0
    for folder, srv in db["servers"].items():
        if srv["owner"] == owner_email:
            disk_used = 0
            if os.path.exists(srv["path"]):
                try:
                    for root, dirs, files in os.walk(srv["path"]):
                        for f in files:
                            fp = os.path.join(root, f)
                            try:
                                disk_used += os.path.getsize(fp)
                            except Exception:
                                pass
                except Exception:
                    pass
            disk_used_mb = round(disk_used / (1024 * 1024), 2)
            total_disk_used_mb += disk_used_mb
            user_servers.append({
                "folder": folder,
                "title": srv["name"],
                "name": srv["name"],
                "server_type": srv.get("server_type", "Python"),
                "status": srv.get("status", "Stopped"),
                "uptime": uptime_str(srv.get("start_time")) if srv.get("status") == "Running" else "0 ثانية",
                "port": srv.get("port", "N/A"),
                "plan": srv.get("plan", "free"),
                "storage_limit": srv.get("storage_limit", 512000),
                "ram_limit": srv.get("ram_limit", 256),
                "cpu_limit": srv.get("cpu_limit", 0.5),
                "disk_used": disk_used_mb,
                "startup_file": srv.get("startup_file", "")
            })
    user = db["users"].get(owner_email, {})
    return jsonify({
        "success": True,
        "servers": user_servers,
        "stats": {
            "used": len(user_servers),
            "total": user.get("max_servers", 2),
            "expiry": user.get("expiry_days", 365),
            "disk_used": round(total_disk_used_mb, 2),
            "disk_total": user.get("storage_limit", 512000),
        }
    })

@app.route('/api/server/add', methods=['POST'])
def add_server():
    if 'email' not in session:
        return jsonify({"success": False, "message": "غير مصرح"}), 401
    
    user = db["users"].get(session['email'])
    if not user:
        return jsonify({"success": False, "message": "مستخدم غير موجود"})
    
    user_srv_count = len([s for s in db["servers"].values() if s["owner"] == session['email']])
    if user_srv_count >= user.get("max_servers", 2):
        return jsonify({"success": False, "message": f"وصلت للحد الأقصى ({user.get('max_servers', 2)}) سيرفر"})
    
    data = request.get_json() or {}
    name = data.get("name", "").strip()
    server_type = data.get("server_type", "Python")
    
    if not name:
        return jsonify({"success": False, "message": "الرجاء إدخال اسم للسيرفر"})
    
    plan_id = user.get("plan", "free")
    plan = db["plans"].get(plan_id, db["plans"]["free"])
    
    safe_email = session['email'].replace("@", "_at_").replace(".", "_dot_")
    folder = f"{safe_email}_{re.sub(r'[^a-zA-Z0-9]', '_', name)}_{int(time.time())}"
    path = os.path.join(get_user_servers_dir(session['email']), folder)
    os.makedirs(path, exist_ok=True)
    assigned_port = get_assigned_port()
    
    db["servers"][folder] = {
        "name": name,
        "owner": session['email'],
        "path": path,
        "server_type": server_type,
        "status": "Stopped",
        "created_at": str(datetime.now()),
        "startup_file": "",
        "pid": None,
        "port": assigned_port,
        "plan": plan_id,
        "storage_limit": plan["storage"],
        "ram_limit": plan["ram"],
        "cpu_limit": plan["cpu"]
    }
    save_db(db)
    return jsonify({"success": True, "message": f"✅ تم إنشاء {server_type} سيرفر: {name}"})

@app.route('/api/server/action/<folder>/<action>', methods=['POST'])
def server_action(folder, action):
    email = session.get('email')
    srv = db["servers"].get(folder)
    if not srv:
        return jsonify({"success": False, "message": "السيرفر غير موجود"})
    if not is_admin(email) and srv["owner"] != email:
        return jsonify({"success": False, "message": "غير مصرح"})
    
    if action == "start":
        if srv.get("status") == "Running":
            return jsonify({"success": False, "message": "الخادم يعمل بالفعل"})
        ok, msg = start_server_process(folder)
        return jsonify({"success": ok, "message": msg})
    elif action == "stop":
        stop_server_process(folder)
        return jsonify({"success": True, "message": "🛑 تم الإيقاف"})
    elif action == "restart":
        restart_server(folder)
        return jsonify({"success": True, "message": "🔄 تم إعادة التشغيل"})
    elif action == "delete":
        stop_server_process(folder)
        if os.path.exists(srv["path"]):
            shutil.rmtree(srv["path"], ignore_errors=True)
        del db["servers"][folder]
        save_db(db)
        return jsonify({"success": True, "message": "🗑 تم الحذف"})
    return jsonify({"success": False})

@app.route('/api/server/stats/<folder>')
def get_server_stats(folder):
    if 'email' not in session:
        return jsonify({"success": False}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session['email']:
        return jsonify({"success": False})
    
    status = srv.get("status", "Stopped")
    logs = "لا توجد مخرجات بعد"
    log_path = os.path.join(srv["path"], "out.log")
    if os.path.exists(log_path):
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.read().split('\n')
                logs = '\n'.join(lines[-500:])
        except Exception:
            pass
    
    mem_info = "0"
    if srv.get("pid") and status == "Running":
        try:
            p = psutil.Process(srv["pid"])
            mem_info = f"{p.memory_info().rss / (1024*1024):.1f}"
        except Exception:
            pass
    
    return jsonify({
        "success": True,
        "status": status,
        "logs": logs,
        "mem": mem_info,
        "uptime": uptime_str(srv.get("start_time")) if status == "Running" else "0 ثانية",
        "port": srv.get("port", "--")
    })

@app.route('/api/files/list/<folder>')
def list_server_files(folder):
    if 'email' not in session:
        return jsonify([]), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session['email']:
        return jsonify([])
    
    path = srv["path"]
    files = []
    try:
        for f in os.listdir(path):
            if f in ["out.log", "server.log", "meta.json", "errors.log"]:
                continue
            fpath = os.path.join(path, f)
            stat = os.stat(fpath)
            size_bytes = stat.st_size
            if size_bytes < 1024:
                size_str = f"{size_bytes} B"
            elif size_bytes < 1024 * 1024:
                size_str = f"{size_bytes/1024:.1f} KB"
            else:
                size_str = f"{size_bytes/(1024*1024):.1f} MB"
            files.append({
                "name": f, "size": size_str, "is_dir": os.path.isdir(fpath),
                "modified": datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M')
            })
    except Exception:
        pass
    return jsonify(sorted(files, key=lambda x: (not x['is_dir'], x['name'].lower())))

@app.route('/api/files/content/<folder>/<path:filename>')
def get_file_content(folder, filename):
    if 'email' not in session:
        return jsonify({"content": ""}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session['email']:
        return jsonify({"content": ""})
    if '..' in filename:
        return jsonify({"content": ""})
    
    fpath = os.path.join(srv["path"], filename)
    if not os.path.exists(fpath) or os.path.isdir(fpath):
        return jsonify({"content": ""})
    try:
        with open(fpath, "r", encoding="utf-8", errors="replace") as f:
            return jsonify({"content": f.read()})
    except Exception:
        return jsonify({"content": "[ملف ثنائي]"})

@app.route('/api/files/save/<folder>/<path:filename>', methods=['POST'])
def save_file_content(folder, filename):
    if 'email' not in session:
        return jsonify({"success": False}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session['email']:
        return jsonify({"success": False})
    if '..' in filename:
        return jsonify({"success": False})
    
    data = request.get_json() or {}
    content = data.get("content", "")
    
    is_safe, msg = scan_code_security(content)
    if not is_safe:
        return jsonify({"success": False, "message": msg})

    fpath = os.path.join(srv["path"], filename)
    try:
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(content)
        return jsonify({"success": True, "message": "✅ تم الحفظ بنجاح"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route('/api/files/upload/<folder>', methods=['POST'])
def upload_files(folder):
    if 'email' not in session:
        return jsonify({"success": False}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session['email']:
        return jsonify({"success": False})
    
    files = request.files.getlist('files[]')
    uploaded = 0
    for f in files:
        try:
            if f and f.filename and '..' not in f.filename:
                content_bytes = f.read()
                
                try:
                    content_str = content_bytes.decode("utf-8", errors="ignore")
                    is_safe, msg = scan_code_security(content_str)
                    if not is_safe:
                        continue
                except Exception:
                    pass
                
                save_path = os.path.join(srv["path"], f.filename)
                with open(save_path, "wb") as sf:
                    sf.write(content_bytes)
                
                if f.filename.lower().endswith('.zip'):
                    try:
                        with zipfile.ZipFile(save_path, 'r') as zf:
                            zf.extractall(srv["path"])
                    except Exception:
                        pass
                
                uploaded += 1
        except Exception:
            pass
    
    if uploaded > 0:
        if srv.get("server_type") == "Node.js":
            detected = detect_node_main_file(srv["path"])
            if detected:
                srv["startup_file"] = detected
                save_db(db)
            threading.Thread(target=auto_install_node_deps, args=(srv["path"], open(os.path.join(srv["path"], "out.log"), "a", encoding="utf-8")), daemon=True).start()
        else:
            detected = detect_main_file(srv["path"])
            if detected:
                srv["startup_file"] = detected
                save_db(db)
            threading.Thread(target=auto_install_deps, args=(srv["path"], open(os.path.join(srv["path"], "out.log"), "a", encoding="utf-8")), daemon=True).start()
            
        return jsonify({"success": True, "message": f"✅ تم رفع الملفات وفك ضغطها بنجاح"})
    return jsonify({"success": False, "message": "فشل الرفع أو تم حظر الملفات لأسباب أمنية"})

@app.route('/api/files/delete/<folder>', methods=['POST'])
def delete_files(folder):
    if 'email' not in session:
        return jsonify({"success": False}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session['email']:
        return jsonify({"success": False})
    
    data = request.get_json() or {}
    names = data.get("names", data.get("name", []))
    if isinstance(names, str):
        names = [names]
    
    deleted = 0
    for name in names:
        if name and '..' not in name:
            fpath = os.path.join(srv["path"], name)
            try:
                if os.path.isdir(fpath):
                    shutil.rmtree(fpath)
                elif os.path.exists(fpath):
                    os.remove(fpath)
                deleted += 1
            except Exception:
                pass
    return jsonify({"success": True, "message": f"🗑 تم حذف {deleted} ملف"})

@app.route('/api/files/create/<folder>', methods=['POST'])
def create_file_api(folder):
    if 'email' not in session:
        return jsonify({"success": False}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session['email']:
        return jsonify({"success": False})
    
    data = request.get_json() or {}
    filename = data.get("filename", "").strip()
    content = data.get("content", "")
    if not filename or '..' in filename:
        return jsonify({"success": False})
    
    is_safe, msg = scan_code_security(content)
    if not is_safe:
        return jsonify({"success": False, "message": msg})

    fpath = os.path.join(srv["path"], filename)
    try:
        if filename.endswith('/'):
            os.makedirs(fpath, exist_ok=True)
        else:
            with open(fpath, "w", encoding="utf-8") as f:
                f.write(content)
            if not srv.get("startup_file"):
                if filename.endswith('.py') or filename.endswith('.js'):
                    srv["startup_file"] = filename
                    save_db(db)
        return jsonify({"success": True, "message": f"✅ تم إنشاء {filename}"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route('/api/files/rename/<folder>', methods=['POST'])
def rename_file(folder):
    if 'email' not in session:
        return jsonify({"success": False}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session['email']:
        return jsonify({"success": False})
    
    data = request.get_json() or {}
    old_name = data.get("old_name", "").strip()
    new_name = data.get("new_name", "").strip()
    if '..' in old_name or '..' in new_name:
        return jsonify({"success": False})
    
    old_path = os.path.join(srv["path"], old_name)
    new_path = os.path.join(srv["path"], new_name)
    if not os.path.exists(old_path):
        return jsonify({"success": False})
    try:
        os.rename(old_path, new_path)
        if srv.get("startup_file") == old_name:
            srv["startup_file"] = new_name
            save_db(db)
        return jsonify({"success": True, "message": f"✅ تم تغيير الاسم"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route('/api/files/unzip/<folder>/<path:filename>', methods=['POST'])
def unzip_file(folder, filename):
    if 'email' not in session:
        return jsonify({"success": False}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session['email']:
        return jsonify({"success": False})
    
    zip_path = os.path.join(srv["path"], filename)
    if not os.path.exists(zip_path):
        return jsonify({"success": False})
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            zf.extractall(srv["path"])
        
        if srv.get("server_type") == "Node.js":
            detected = detect_node_main_file(srv["path"])
        else:
            detected = detect_main_file(srv["path"])
        if detected:
            srv["startup_file"] = detected
            save_db(db)

        return jsonify({"success": True, "message": f"✅ تم فك الضغط واكتشاف ملف التشغيل"})
    except Exception:
        return jsonify({"success": False, "message": "فشل فك الضغط"})

@app.route('/api/server/set-startup/<folder>', methods=['POST'])
def set_startup_file(folder):
    if 'email' not in session:
        return jsonify({"success": False}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session['email']:
        return jsonify({"success": False})
    
    data = request.get_json() or {}
    filename = data.get("filename", "").strip()
    if not filename or '..' in filename:
        return jsonify({"success": False})
    
    srv["startup_file"] = filename
    save_db(db)
    return jsonify({"success": True, "message": f"✅ تم تعيين {filename}"})

@app.route('/api/server/install/<folder>', methods=['POST'])
def install_requirements(folder):
    if 'email' not in session:
        return jsonify({"success": False}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session['email']:
        return jsonify({"success": False})
    
    if srv.get("server_type") == "Node.js":
        threading.Thread(target=auto_install_node_deps, args=(srv["path"], open(os.path.join(srv["path"], "out.log"), "a", encoding="utf-8")), daemon=True).start()
    else:
        threading.Thread(target=auto_install_deps, args=(srv["path"], open(os.path.join(srv["path"], "out.log"), "a", encoding="utf-8")), daemon=True).start()
    return jsonify({"success": True, "message": "📦 بدأ تثبيت المكتبات"})

@app.route('/api/bot/verify', methods=['POST'])
def bot_verify():
    data = request.get_json() or {}
    api_key = data.get('api_key', '').strip()
    if not api_key:
        return jsonify({"success": False})
    email, user = get_user_by_api_key(api_key)
    if not email:
        return jsonify({"success": False})
    return jsonify({
        "success": True, "email": email, "username": email,
        "is_admin": is_admin(email), "max_servers": user.get("max_servers", 2)
    })

@app.route('/api/bot/servers', methods=['GET'])
def bot_list_servers():
    api_key = request.args.get('api_key')
    if not api_key:
        return jsonify({"success": False}), 401
    email, _ = get_user_by_api_key(api_key)
    if not email:
        return jsonify({"success": False}), 401
    
    user_servers = []
    for folder, srv in db["servers"].items():
        if srv["owner"] == email:
            user_servers.append({
                "folder": folder, "title": srv["name"], "name": srv["name"],
                "status": srv.get("status", "Stopped"), "port": srv.get("port", "N/A"),
                "type": srv.get("server_type", "Python"), "server_type": srv.get("server_type", "Python"),
                "uptime": uptime_str(srv.get("start_time")) if srv.get("status") == "Running" else "0 ثانية"
            })
    return jsonify({"success": True, "servers": user_servers})

@app.route('/api/bot/server/action', methods=['POST'])
def bot_server_action():
    data = request.get_json() or {}
    api_key = data.get('api_key')
    folder = data.get('folder')
    action = data.get('action')
    if not all([api_key, folder, action]):
        return jsonify({"success": False}), 400
    email, _ = get_user_by_api_key(api_key)
    if not email:
        return jsonify({"success": False}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != email:
        return jsonify({"success": False}), 403
    
    if action == "start":
        ok, msg = start_server_process(folder)
        return jsonify({"success": ok, "message": msg})
    elif action == "stop":
        stop_server_process(folder)
        return jsonify({"success": True, "message": "🛑 تم الإيقاف"})
    elif action == "restart":
        restart_server(folder)
        return jsonify({"success": True, "message": "🔄 تم إعادة التشغيل"})
    elif action == "delete":
        stop_server_process(folder)
        if os.path.exists(srv["path"]):
            shutil.rmtree(srv["path"], ignore_errors=True)
        del db["servers"][folder]
        save_db(db)
        return jsonify({"success": True, "message": "🗑 تم الحذف"})
    return jsonify({"success": False})

@app.route('/api/bot/console', methods=['GET'])
def bot_console():
    api_key = request.args.get('api_key')
    folder = request.args.get('folder')
    if not api_key or not folder:
        return jsonify({"success": False}), 400
    email, _ = get_user_by_api_key(api_key)
    if not email:
        return jsonify({"success": False}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != email:
        return jsonify({"success": False}), 403
    
    log_path = os.path.join(srv["path"], "out.log")
    logs = "لا توجد مخرجات بعد"
    if os.path.exists(log_path):
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                logs = f.read()[-3500:]
        except Exception:
            pass
    return jsonify({"success": True, "logs": logs})

@app.route('/api/bot/errors', methods=['GET'])
def bot_errors():
    api_key = request.args.get('api_key')
    folder = request.args.get('folder')
    if not api_key or not folder:
        return jsonify({"success": False}), 400
    email, _ = get_user_by_api_key(api_key)
    if not email:
        return jsonify({"success": False}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != email:
        return jsonify({"success": False}), 403
    
    err_path = os.path.join(srv["path"], "errors.log")
    errors = "✅ لا توجد أخطاء"
    if os.path.exists(err_path):
        try:
            with open(err_path, "r", encoding="utf-8", errors="ignore") as f:
                errors = f.read()[-3500:]
        except Exception:
            pass
    return jsonify({"success": True, "errors": errors})

@app.route('/api/bot/install', methods=['POST'])
def bot_install():
    data = request.get_json() or {}
    api_key = data.get('api_key')
    folder = data.get('folder')
    if not api_key or not folder:
        return jsonify({"success": False}), 400
    email, _ = get_user_by_api_key(api_key)
    if not email:
        return jsonify({"success": False}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != email:
        return jsonify({"success": False}), 403
    
    if srv.get("server_type") == "Node.js":
        threading.Thread(target=auto_install_node_deps, args=(srv["path"], open(os.path.join(srv["path"], "out.log"), "a", encoding="utf-8")), daemon=True).start()
    else:
        threading.Thread(target=auto_install_deps, args=(srv["path"], open(os.path.join(srv["path"], "out.log"), "a", encoding="utf-8")), daemon=True).start()
    return jsonify({"success": True, "message": "📦 بدأ تثبيت المكتبات"})

@app.route('/api/bot/create_server', methods=['POST'])
def bot_create_server():
    data = request.get_json() or {}
    api_key = data.get('api_key')
    if not api_key:
        return jsonify({"success": False, "message": "غير مصرح"}), 401
    email, user = get_user_by_api_key(api_key)
    if not email:
        return jsonify({"success": False, "message": "غير مصرح"}), 401
    
    user_srv_count = len([s for s in db["servers"].values() if s["owner"] == email])
    if user_srv_count >= user.get("max_servers", 2):
        return jsonify({"success": False, "message": f"وصلت للحد الأقصى ({user.get('max_servers', 2)}) سيرفر"})
    
    name = data.get("name", "").strip()
    server_type = data.get("server_type", "Python")
    if not name:
        return jsonify({"success": False, "message": "الرجاء إدخال اسم للسيرفر"})
    
    plan_id = user.get("plan", "free")
    plan = db["plans"].get(plan_id, db["plans"]["free"])
    
    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    folder = f"{safe_email}_{re.sub(r'[^a-zA-Z0-9]', '_', name)}_{int(time.time())}"
    path = os.path.join(get_user_servers_dir(email), folder)
    os.makedirs(path, exist_ok=True)
    assigned_port = get_assigned_port()
    
    db["servers"][folder] = {
        "name": name, "owner": email, "path": path, "server_type": server_type,
        "status": "Stopped", "created_at": str(datetime.now()), "startup_file": "",
        "pid": None, "port": assigned_port, "plan": plan_id,
        "storage_limit": plan["storage"], "ram_limit": plan["ram"], "cpu_limit": plan["cpu"]
    }
    save_db(db)
    return jsonify({"success": True, "message": f"✅ تم إنشاء {server_type} سيرفر: {name}"})

WAITING_FOR_API_KEY, WAITING_FOR_NEW_SERVER_NAME, WAITING_FOR_SERVER_TYPE, WAITING_FOR_DELETE_USERNAME = range(4)

def api_request(endpoint, method="GET", data=None, params=None, api_key=None):
    url = f"{API_BASE_URL}{endpoint}"
    try:
        if method == "GET":
            p = dict(params or {})
            if api_key: p["api_key"] = api_key
            resp = requests.get(url, params=p, timeout=30)
        else:
            d = dict(data or {})
            if api_key and "api_key" not in d: d["api_key"] = api_key
            resp = requests.post(url, json=d, timeout=30)
        return resp.json() if resp.ok else {"success": False, "message": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"success": False, "message": str(e)}

def is_admin_tg(update: Update) -> bool:
    return update.effective_chat.id in ADMIN_TELEGRAM_IDS

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text("📚 المساعدة:\n\nهذا البوت يعمل بشكل مستمر على خادم 𝗘𝗛𝗔𝗕 𝐇𝐎𝐒𝐓\nللاشتراك أو الاستفسار: @Y_20_20")

async def info_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text("ℹ️ معلومات البوت:\n\n🤖 الخدمة: 𝗘𝗛𝗔𝗕 𝐇𝐎𝐒𝐓\n✅ الحالة: نشط ومستمر\n🛠 المطور: @Y_20_20")

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_message = update.message.text
    await update.message.reply_text(f"📨 تم استقبال رسالتك:\n\n{user_message}\n\nشكراً لاستخدامك 𝗘𝗛𝗔𝗕 𝐇𝐎𝐒𝐓!\n🛠 @Y_20_20")

async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.error(msg="Exception while handling an update:", exc_info=context.error)

async def show_main_menu(update: Update, context: ContextTypes.DEFAULT_TYPE, edit=False):
    api_key = context.user_data.get("api_key")
    username = context.user_data.get("username", "")
    is_adm = is_admin_tg(update)

    keyboard = []
    if api_key:
        keyboard.append([
            InlineKeyboardButton("📁 سيرفراتي", callback_data="my_servers"),
            InlineKeyboardButton("➕ إنشاء سيرفر", callback_data="create_server"),
        ])
        keyboard.append([
            InlineKeyboardButton("🔑 تغيير API Key", callback_data="change_api"),
            InlineKeyboardButton("🚪 تسجيل خروج", callback_data="logout"),
        ])
    else:
        keyboard.append([InlineKeyboardButton("🔑 ربط API Key", callback_data="enter_api")])

    if is_adm:
        keyboard.append([InlineKeyboardButton("👑 لوحة الإدارة", callback_data="admin_panel")])

    keyboard.append([InlineKeyboardButton("💬 تواصل مع المطور @Y_20_20", url="https://t.me/Y_20_20")])

    text = "━━━━━━━━━━━━━━━━━━━━\n      𝗘𝗛𝗔𝗕 𝐇𝐎𝐒𝐓 🚀\n━━━━━━━━━━━━━━━━━━━━\n"
    if username: text += f"👤 أهلاً، *{username}*!\n"
    text += "✅ متصل بالنظام\n" if api_key else "⚠️ يجب ربط API Key أولاً\n"
    text += f"\n{DEVELOPER_INFO}"

    markup = InlineKeyboardMarkup(keyboard)
    try:
        if edit and update.callback_query:
            await update.callback_query.edit_message_text(text, parse_mode="Markdown", reply_markup=markup)
        elif update.message:
            await update.message.reply_text(text, parse_mode="Markdown", reply_markup=markup)
        else:
            await update.callback_query.edit_message_text(text, parse_mode="Markdown", reply_markup=markup)
    except Exception:
        pass

async def show_servers_list(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    api_key = context.user_data.get("api_key")
    if not api_key:
        await query.edit_message_text("❌ يجب ربط API Key أولاً.")
        return

    result = api_request("/api/bot/servers", api_key=api_key)
    if not result or not result.get("success"):
        await query.edit_message_text("❌ فشل جلب السيرفرات. تحقق من صحة API Key.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 رجوع", callback_data="main_menu")]]))
        return

    servers = result.get("servers", [])
    if not servers:
        await query.edit_message_text("📭 لا توجد سيرفرات. أنشئ سيرفرك الأول الآن!", reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("➕ إنشاء سيرفر", callback_data="create_server")],
            [InlineKeyboardButton("🔙 رجوع", callback_data="main_menu")]
        ]))
        return

    await query.edit_message_text(f"📋 لديك *{len(servers)}* سيرفر:", parse_mode="Markdown")

    for srv in servers:
        status_emoji = "🟢" if srv["status"] == "Running" else "⚫"
        srv_type = srv.get("type", "Python")
        type_icon = "🐍" if srv_type == "Python" else "🟨"

        text = f"━━━━━━━━━━━━━━━━━━━━\n{status_emoji} *{srv['title']}*\n━━━━━━━━━━━━━━━━━━━━\n{type_icon} النوع: `{srv_type}`\n📊 الحالة: `{srv['status']}`\n🔌 المنفذ: `{srv['port']}`\n⏱ وقت التشغيل: {srv['uptime']}"
        folder = srv["folder"]
        keyboard = [
            [InlineKeyboardButton("▶️ تشغيل", callback_data=f"srv_start|{folder}"), InlineKeyboardButton("⏹ إيقاف", callback_data=f"srv_stop|{folder}"), InlineKeyboardButton("🔄 إعادة", callback_data=f"srv_restart|{folder}")],
            [InlineKeyboardButton("🖥 كونسول", callback_data=f"console|{folder}"), InlineKeyboardButton("⚠️ أخطاء", callback_data=f"errors|{folder}"), InlineKeyboardButton("🗑 حذف", callback_data=f"srv_delete|{folder}")],
            [InlineKeyboardButton("📦 تثبيت مكتبات تلقائياً", callback_data=f"install|{folder}")]
        ]
        await query.message.reply_text(text, parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(keyboard))

    await query.message.reply_text("━━━━━━━━━━━━━━━━━━━━", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 القائمة الرئيسية", callback_data="main_menu")]]))

async def show_admin_panel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    if not is_admin_tg(update):
        await query.edit_message_text("❌ غير مصرح لك بالدخول.")
        return

    api_key = context.user_data.get("api_key")
    result = api_request("/api/admin/users", api_key=api_key)
    users = result.get("users", []) if result and result.get("success") else []

    text = f"━━━━━━━━━━━━━━━━━━━━\n  👑 لوحة إدارة 𝗘𝗛𝗔𝗕 𝐇𝐎𝐒𝐓\n━━━━━━━━━━━━━━━━━━━━\n👥 المستخدمين: *{len(users)}*\n━━━━━━━━━━━━━━━━━━━━\n"
    for u in users[:10]:
        text += f"• `{u['username']}` | {u.get('max_servers', 1)} سيرفر\n"

    keyboard = [
        [InlineKeyboardButton("📊 إحصائيات النظام", callback_data="admin_stats")],
        [InlineKeyboardButton("🔙 رجوع", callback_data="main_menu")]
    ]
    await query.edit_message_text(text, parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(keyboard))

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    api_key = context.user_data.get("api_key")
    if api_key:
        result = api_request("/api/bot/verify", method="POST", data={"api_key": api_key})
        if result and result.get("success"):
            context.user_data["username"] = result.get("username")
            await show_main_menu(update, context)
            return ConversationHandler.END
        context.user_data.clear()

    keyboard = [
        [InlineKeyboardButton("🔑 إدخال API Key", callback_data="enter_api")],
        [InlineKeyboardButton("💬 تواصل مع المطور @Y_20_20", url="https://t.me/Y_20_20")]
    ]
    await update.message.reply_text(
        "━━━━━━━━━━━━━━━━━━━━\n      𝗘𝗛𝗔𝗕 𝐇𝐎𝐒𝐓 🚀\n━━━━━━━━━━━━━━━━━━━━\nللاشتراك والحصول على حساب:\n📬 تواصل مع المطور: @Y_20_20\n\n" + DEVELOPER_INFO,
        parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(keyboard)
    )
    return WAITING_FOR_API_KEY

async def handle_api_key(update: Update, context: ContextTypes.DEFAULT_TYPE):
    api_key = update.message.text.strip()
    result = api_request("/api/bot/verify", method="POST", data={"api_key": api_key})
    if not result or not result.get("success"):
        await update.message.reply_text("❌ *مفتاح API غير صالح!*\n\nتحقق من الكود وحاول مرة أخرى أو تواصل مع المطور: @Y_20_20", parse_mode="Markdown")
        return WAITING_FOR_API_KEY

    context.user_data["api_key"] = api_key
    context.user_data["username"] = result.get("username")
    context.user_data["is_admin"] = result.get("is_admin", False)

    await update.message.reply_text(f"✅ *تم الربط بنجاح!*\n👤 مرحباً *{result.get('username')}*!", parse_mode="Markdown")
    await show_main_menu(update, context)
    return ConversationHandler.END

async def receive_server_name(update: Update, context: ContextTypes.DEFAULT_TYPE):
    name = update.message.text.strip()
    context.user_data["pending_server_name"] = name
    keyboard = [
        [InlineKeyboardButton("🐍 Python", callback_data="server_type_python"), InlineKeyboardButton("🟨 Node.js", callback_data="server_type_nodejs")]
    ]
    await update.message.reply_text(f"📦 *اختر نوع السيرفر:*\n\nالاسم: `{name}`", parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(keyboard))
    return WAITING_FOR_SERVER_TYPE

async def receive_server_type(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    srv_type = "Python" if query.data == "server_type_python" else "Node.js"
    name = context.user_data.get("pending_server_name", "Server")

    result = api_request("/api/bot/create_server", method="POST", data={
        "api_key": context.user_data["api_key"], "name": name, "server_type": srv_type
    })

    type_icon = "🐍" if srv_type == "Python" else "🟨"
    if result and result.get("success"):
        await query.edit_message_text(f"✅ *تم إنشاء السيرفر بنجاح!*\n\n📛 الاسم: `{name}`\n{type_icon} النوع: `{srv_type}`\n\nارفع ملفاتك عبر لوحة التحكم الآن.", parse_mode="Markdown")
    else:
        await query.edit_message_text(f"❌ *فشل الإنشاء!*\n{result.get('message', 'خطأ')}", parse_mode="Markdown")

    await show_main_menu(update, context)
    return ConversationHandler.END

async def show_console(update: Update, context: ContextTypes.DEFAULT_TYPE, folder: str):
    query = update.callback_query
    result = api_request("/api/bot/console", params={"folder": folder}, api_key=context.user_data.get("api_key"))
    if result and result.get("success"):
        logs = result.get("logs", "لا توجد مخرجات")
        if len(logs) > 3500: logs = "...\n" + logs[-3500:]
        keyboard = [[InlineKeyboardButton("🔄 تحديث", callback_data=f"console|{folder}"), InlineKeyboardButton("🔙 رجوع", callback_data="my_servers")]]
        await query.edit_message_text(f"🖥 *كونسول السيرفر*\n```\n{logs}\n```", parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(keyboard))
    else:
        await query.edit_message_text("❌ فشل جلب الكونسول")

async def show_errors(update: Update, context: ContextTypes.DEFAULT_TYPE, folder: str):
    query = update.callback_query
    result = api_request("/api/bot/errors", params={"folder": folder}, api_key=context.user_data.get("api_key"))
    if result and result.get("success"):
        errors = result.get("errors", "✅ لا توجد أخطاء")
        if len(errors) > 3500: errors = "...\n" + errors[-3500:]
        keyboard = [[InlineKeyboardButton("🔙 رجوع", callback_data="my_servers")]]
        await query.edit_message_text(f"⚠️ *سجل الأخطاء*\n```\n{errors}\n```", parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(keyboard))
    else:
        await query.edit_message_text("❌ فشل جلب سجل الأخطاء")

async def admin_stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    metrics = api_request("/api/system/metrics")
    cpu = metrics.get("cpu", "?") if metrics else "?"
    ram = metrics.get("memory", "?") if metrics else "?"
    disk = metrics.get("disk", "?") if metrics else "?"
    await query.edit_message_text(
        f"━━━━━━━━━━━━━━━━━━━━\n  📊 إحصائيات النظام\n━━━━━━━━━━━━━━━━━━━━\n🖥 CPU:  *{cpu}%*\n💾 RAM:  *{ram}%*\n💿 Disk: *{disk}%*",
        parse_mode="Markdown", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 رجوع", callback_data="admin_panel")]])
    )

async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    data = query.data

    if data == "main_menu":
        await show_main_menu(update, context, edit=True)
    elif data == "my_servers":
        await show_servers_list(update, context)
    elif data in ("enter_api", "change_api"):
        context.user_data.pop("api_key", None)
        await query.edit_message_text("🔑 *أدخل API Key الخاص بك:*\n\nيمكنك الحصول عليه من لوحة التحكم في الموقع.", parse_mode="Markdown")
        return WAITING_FOR_API_KEY
    elif data == "logout":
        context.user_data.clear()
        await query.edit_message_text("🚪 تم تسجيل الخروج.\nاستخدم /start للدخول مجدداً.")
    elif data == "create_server":
        await query.edit_message_text("➕ *إنشاء سيرفر جديد*\n\n📝 أرسل اسم السيرفر:", parse_mode="Markdown")
        return WAITING_FOR_NEW_SERVER_NAME
    elif data == "admin_panel":
        await show_admin_panel(update, context)
    elif data == "admin_stats":
        await admin_stats(update, context)

    elif "|" in data:
        cmd, value = data.split("|", 1)
        api_key = context.user_data.get("api_key")

        if cmd in ("srv_start", "srv_stop", "srv_restart", "srv_delete"):
            action = cmd.replace("srv_", "")
            result = api_request("/api/bot/server/action", method="POST", data={"api_key": api_key, "folder": value, "action": action})
            if result and result.get("success"):
                await query.answer(result.get("message", "✅ تم")[:200], show_alert=True)
            else:
                await query.answer(f"❌ {result.get('message', 'فشل')}"[:200], show_alert=True)
            await show_servers_list(update, context)
        elif cmd == "console":
            await show_console(update, context, value)
        elif cmd == "errors":
            await show_errors(update, context, value)
        elif cmd == "install":
            result = api_request("/api/bot/install", method="POST", data={"api_key": api_key, "folder": value})
            msg = result.get("message", "✅ جاري التثبيت") if result and result.get("success") else f"❌ {result.get('message', 'فشل')}"
            await query.edit_message_text(f"📦 *تثبيت المكتبات*\n\n{msg}\n\nتابع الكونسول للتفاصيل.", parse_mode="Markdown", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🖥 كونسول", callback_data=f"console|{value}"), InlineKeyboardButton("🔙 رجوع", callback_data="my_servers")]]))

    return ConversationHandler.END

def run_telegram_bot():
    try:
        print("\n" + "="*60)
        print(f" 🤖 𝗘𝗛𝗔𝗕 𝐇𝐎𝐒𝐓 - جاري تشغيل بوت التحكم المدمج")
        print(" 🚀 يتم الآن الاتصال بخوادم تليجرام...")
        print("="*60 + "\n")
        
        application = Application.builder().token(BOT_TOKEN).build()
        
        conv = ConversationHandler(
            entry_points=[
                CommandHandler("start", start),
                CommandHandler("help", help_command),
                CommandHandler("info", info_command),
                CallbackQueryHandler(button_callback),
            ],
            states={
                WAITING_FOR_API_KEY: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_api_key)],
                WAITING_FOR_NEW_SERVER_NAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, receive_server_name)],
                WAITING_FOR_SERVER_TYPE: [CallbackQueryHandler(receive_server_type, pattern="^server_type_")],
            },
            fallbacks=[CommandHandler("start", start)],
            per_user=True, per_chat=True,
        )

        application.add_handler(conv)
        application.add_handler(CommandHandler("help", help_command))
        application.add_handler(CommandHandler("info", info_command))
        application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
        application.add_error_handler(error_handler)
        
        print(" ✅ بوت 𝗘𝗛𝗔𝗕 𝐇𝐎𝐒𝐓 جاهز الآن ويعمل بشكل مستمر!")
        print(" 📡 الحالة: نشط وينتظر التفاعلات...\n")
        
        application.run_polling(drop_pending_updates=True)
    except Exception as e:
        logger.error(f"❌ خطأ في تشغيل بوت تيليجرام: {str(e)}")

if __name__ == "__main__":
    threading.Thread(target=run_telegram_bot, daemon=True).start()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
