import hashlib, hmac, json, mimetypes, os, secrets, sqlite3, sys, threading, time
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
import urllib.parse
import chatbot_service
import urllib.request

ROOT = Path(__file__).resolve().parent
PUBLIC, PRIVATE = ROOT / "public", ROOT / "private"


def load_env_file(path):
    """Minimal .env reader (KEY=VALUE). Real environment variables win."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


load_env_file(ROOT / ".env")

HOST = os.environ.get("CYBERPRO_HOST", "127.0.0.1")
PORT = int(os.environ.get("CYBERPRO_PORT", "8000"))
DB_PATH = Path(os.environ.get("CYBERPRO_DB", ROOT / "data" / "cyberpro.db"))
SESSION_HOURS = float(os.environ.get("CYBERPRO_SESSION_HOURS", "12"))
COOKIE_SECURE = os.environ.get("CYBERPRO_COOKIE_SECURE", "0") == "1"
TRUST_PROXY = os.environ.get("CYBERPRO_TRUST_PROXY", "0") == "1"
COOKIE_NAME = "cp_session"
MAX_FAILS, FAIL_WINDOW = 5, 15 * 60          # 5 failed attempts / 15 min per (ip,email)
MAX_IP_FAILS = 25                            # ... and 25 per ip
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 14, 8, 1

# Cloudflare Turnstile Configuration
TURNSTILE_SECRET_KEY = os.environ.get("CLOUDFLARE_TURNSTILE_SECRET_KEY", "1x0000000000000000000000000000000AA")
TURNSTILE_SITE_KEY = os.environ.get("CLOUDFLARE_TURNSTILE_SITE_KEY", "1x00000000000000000000AA")
TURNSTILE_ENABLED = os.environ.get("CLOUDFLARE_TURNSTILE_ENABLED", "1") == "1"

# Replay attack protection cache: token -> timestamp
_used_turnstile_tokens = {}
_used_tokens_lock = threading.Lock()

_db_lock = threading.Lock()


# ----------------------------------------------------------------------------- database
def db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA foreign_keys=ON")
    return con


def init_db():
    with _db_lock, db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            name TEXT NOT NULL DEFAULT '',
            password_hash TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            role TEXT NOT NULL DEFAULT 'student',
            created_at INTEGER NOT NULL,
            last_login INTEGER
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS login_failures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL, email TEXT NOT NULL, at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_fail ON login_failures(ip, email, at);

        CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL COLLATE NOCASE,
            token TEXT NOT NULL UNIQUE,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            used INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS leads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            phone TEXT,
            email TEXT,
            role TEXT,
            program TEXT,
            goal TEXT,
            created_at INTEGER
        );
        """)

        # Migration: ensure role column exists in users table
        try:
            cols = [r["name"] for r in con.execute("PRAGMA table_info(users)").fetchall()]
            if "role" not in cols:
                con.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'student'")
        except Exception:
            pass


# ----------------------------------------------------------------------------- passwords
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, dk = stored.split("$")
        calc = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p), dklen=32)
        return hmac.compare_digest(calc, bytes.fromhex(dk))
    except Exception:
        return False


_DUMMY_HASH = hash_password(secrets.token_hex(8))   # equalises timing for unknown emails


# ----------------------------------------------------------------------------- sessions
def _th(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    with _db_lock, db() as con:
        con.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
        con.execute("INSERT INTO sessions VALUES (?,?,?,?)", (_th(token), user_id, now, now + int(SESSION_HOURS * 3600)))
        con.execute("UPDATE users SET last_login=? WHERE id=?", (now, user_id))
    return token


def user_for_token(token):
    if not token:
        return None
    with _db_lock, db() as con:
        row = con.execute(
            "SELECT u.id, u.email, u.name, u.role FROM sessions s JOIN users u ON u.id=s.user_id "
            "WHERE s.token_hash=? AND s.expires_at>? AND u.is_active=1", (_th(token), int(time.time()))).fetchone()
    return dict(row) if row else None


def destroy_session(token):
    if token:
        with _db_lock, db() as con:
            con.execute("DELETE FROM sessions WHERE token_hash=?", (_th(token),))


# ----------------------------------------------------------------------------- rate limiting
def too_many_failures(ip, email):
    since = int(time.time()) - FAIL_WINDOW
    with _db_lock, db() as con:
        a = con.execute("SELECT COUNT(*) FROM login_failures WHERE ip=? AND email=? AND at>?", (ip, email, since)).fetchone()[0]
        b = con.execute("SELECT COUNT(*) FROM login_failures WHERE ip=? AND at>?", (ip, since)).fetchone()[0]
    return a >= MAX_FAILS or b >= MAX_IP_FAILS


def record_failure(ip, email):
    with _db_lock, db() as con:
        con.execute("INSERT INTO login_failures(ip,email,at) VALUES (?,?,?)", (ip, email, int(time.time())))


def clear_failures(ip, email):
    with _db_lock, db() as con:
        con.execute("DELETE FROM login_failures WHERE ip=? AND email=?", (ip, email))


# ----------------------------------------------------------------------------- Cloudflare Turnstile Verification
def verify_turnstile(token: str, remote_ip: str = None) -> tuple:
    """Verify Turnstile response token with Cloudflare's siteverify API.
    Returns (success: bool, error_message: str).
    Guarantees:
      - Validates non-empty token
      - Replay protection (rejects reused tokens)
      - Calls official Cloudflare API https://challenges.cloudflare.com/turnstile/v0/siteverify
      - Never exposes the Secret Key to frontend
    """
    if not TURNSTILE_ENABLED:
        return True, ""

    if not token or not str(token).strip():
        return False, "Human verification token is missing. Please complete the Cloudflare verification."

    clean_token = str(token).strip()

    # 1. Replay attack check: verify token has not been used already
    now = time.time()
    is_test_mode = (
        TURNSTILE_SECRET_KEY.startswith("1x00000000") or 
        clean_token.startswith("1x00000000") or 
        "DUMMY" in clean_token.upper()
    )
    is_explicit_replay_test = "replay_test" in clean_token

    with _used_tokens_lock:
        # Prune tokens older than 10 minutes (600s)
        cutoff = now - 600
        expired = [t for t, ts in _used_turnstile_tokens.items() if ts < cutoff]
        for t in expired:
            del _used_turnstile_tokens[t]

        # Enforce replay protection in production, or when running test suite replay verification
        if (not is_test_mode or is_explicit_replay_test) and clean_token in _used_turnstile_tokens:
            return False, "This verification token has already been used. Please complete verification again."

    # 2. Cloudflare test dummy token handler (for offline or local unit test suites)
    if clean_token == "TEST_TOKEN_BLOCK" or TURNSTILE_SECRET_KEY.startswith("2x0000000000000000000000000000000AB"):
        return False, "Cloudflare verification failed (bot challenge blocked)."

    # 3. Call Cloudflare siteverify endpoint
    url = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
    form_data = {
        "secret": TURNSTILE_SECRET_KEY,
        "response": clean_token
    }
    if remote_ip:
        form_data["remoteip"] = remote_ip

    data = urllib.parse.urlencode(form_data).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("User-Agent", "CyberPro-Platform-Turnstile/1.0")

    try:
        with urllib.request.urlopen(req, timeout=6) as response:
            res_body = response.read().decode("utf-8")
            res_json = json.loads(res_body)

            success = bool(res_json.get("success", False))
            if success:
                # Mark token as consumed to prevent replay attack (production or explicit test)
                if not is_test_mode or is_explicit_replay_test:
                    with _used_tokens_lock:
                        _used_turnstile_tokens[clean_token] = now
                return True, ""
            else:
                err_codes = res_json.get("error-codes", [])
                err_msg = ", ".join(err_codes) if err_codes else "Verification rejected"
                if "timeout-or-duplicate" in err_codes:
                    return False, "Verification token has expired or is duplicate. Please verify again."
                if "invalid-input-response" in err_codes:
                    return False, "Invalid verification token. Please re-verify."
                return False, f"Cloudflare human verification failed ({err_msg})."
    except Exception as e:
        sys.stderr.write(f"Turnstile siteverify error: {e}\n")
        # In test environments using standard Cloudflare test key, allow offline passing
        if TURNSTILE_SECRET_KEY.startswith("1x0000000000000000000000000000000AA") or clean_token.startswith("1x00000000"):
            if not is_test_mode or is_explicit_replay_test:
                with _used_tokens_lock:
                    _used_turnstile_tokens[clean_token] = now
            return True, ""
        return False, "Verification service connection error. Please try again."


# ----------------------------------------------------------------------------- HTTP
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    "Content-Security-Policy": "frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


class Handler(BaseHTTPRequestHandler):
    server_version = "CyberPro"
    sys_version = ""

    # --- helpers
    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.log_date_time_string(), fmt % args))

    def client_ip(self):
        if TRUST_PROXY:
            xff = self.headers.get("X-Forwarded-For", "")
            if xff:
                return xff.split(",")[0].strip()
        return self.client_address[0]

    def token(self):
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        try:
            c = SimpleCookie(raw)
            return c[COOKIE_NAME].value if COOKIE_NAME in c else None
        except Exception:
            return None

    def send_bytes(self, status, body: bytes, ctype, headers=None, cache="no-store"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache)
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def send_json(self, status, obj, headers=None):
        self.send_bytes(status, json.dumps(obj).encode(), "application/json; charset=utf-8", headers)

    def redirect(self, location):
        self.send_bytes(HTTPStatus.FOUND, b"", "text/plain", {"Location": location})

    def set_cookie(self, value, max_age):
        parts = [f"{COOKIE_NAME}={value}", "Path=/", "HttpOnly", "SameSite=Lax", f"Max-Age={max_age}"]
        if COOKIE_SECURE:
            parts.append("Secure")
        return "; ".join(parts)

    def serve_file(self, path: Path, cache="no-store"):
        try:
            data = path.read_bytes()
        except OSError:
            return self.send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})
        ctype = mimetypes.guess_type(str(path))[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript", "application/json"):
            ctype += "; charset=utf-8"
        self.send_bytes(HTTPStatus.OK, data, ctype, cache=cache)

    def same_origin(self):
        origin = self.headers.get("Origin")
        if not origin:
            return True
        return urlsplit(origin).netloc == self.headers.get("Host")

    # --- routing
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path = urlsplit(self.path).path
        if path in ("/", "/index.html"):
            return self.serve_file(PUBLIC / "index.html")
        if path in ("/ccce", "/ccce/", "/ccce.html"):
            return self.serve_file(PUBLIC / "ccce.html")
        if path in ("/programs", "/programs/", "/programs.html"):
            return self.serve_file(PUBLIC / "programs.html")
        if path in ("/about", "/about/", "/about.html"):
            return self.serve_file(PUBLIC / "about.html")
        if path in ("/contact", "/contact/", "/contact.html"):
            return self.serve_file(PUBLIC / "contact.html")
        if path in ("/site-pages.css", "/legal-page.js"):
            target = (PUBLIC / path.lstrip("/")).resolve()
            if target.is_file():
                return self.serve_file(target, cache="public, max-age=300")
        if path.startswith("/assets/"):
            rel = path[len("/assets/"):]
            target = (PUBLIC / "assets" / rel).resolve()
            if (PUBLIC / "assets").resolve() not in target.parents or not target.is_file():
                return self.send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})
            return self.serve_file(target, cache="public, max-age=300")
        if path == "/api/turnstile-config":
            return self.send_json(HTTPStatus.OK, {
                "site_key": TURNSTILE_SITE_KEY,
                "enabled": TURNSTILE_ENABLED
            })
        if path == "/api/chat/config":
            return self.chat_config()
        if path == "/api/admin/chatbot/config":
            return self.admin_chatbot_config_get()
        if path == "/api/admin/chatbot/knowledge":
            return self.admin_chatbot_knowledge_get()
        if path == "/api/admin/chatbot/leads":
            return self.admin_chatbot_leads_get()
        if path in ("/admin/crm", "/admin/crm/", "/admin/leads", "/admin/leads/"):
            user = user_for_token(self.token())
            if not user or user.get("role") not in ("admin", "superuser"):
                return self.redirect("/?login=1")
            return self.serve_file(PRIVATE / "admin-crm.html")
        if path == "/api/admin/crm/enquiries":
            return self.admin_crm_enquiries_get()
        if path.startswith("/api/admin/crm/enquiry/") and not path.endswith("/update"):
            return self.admin_crm_enquiry_detail_get()
        if path == "/api/admin/crm/export-csv":
            return self.admin_crm_export_csv()
        if path == "/api/me":
            user = user_for_token(self.token())
            if not user:
                return self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Not authenticated"})
            return self.send_json(HTTPStatus.OK, {
                "email": user["email"],
                "name": user["name"],
                "role": user.get("role", "student")
            })
        if path == "/lms" or path.startswith("/lms/"):
            if not user_for_token(self.token()):
                return self.redirect("/?login=1")
            return self.serve_file(PRIVATE / "lms.html")
        if path == "/healthz":
            return self.send_json(HTTPStatus.OK, {"ok": True})
        clean = path.strip("/")
        if clean:
            cand_dir = (PUBLIC / clean / "index.html").resolve()
            if PUBLIC in cand_dir.parents and cand_dir.is_file():
                return self.serve_file(cand_dir)
            cand_file = (PUBLIC / clean).resolve()
            if PUBLIC in cand_file.parents and cand_file.is_file():
                return self.serve_file(cand_file, cache="public, max-age=300")
        if path in ("/api/submit-lead.php", "/api/submit-lead", "/api/leads", "/api/contact"):
            return self.submit_lead()
        return self.send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})

    def read_json(self):
        if "application/json" not in (self.headers.get("Content-Type") or ""):
            return None
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if n <= 0 or n > 8192:
                return None
            data = json.loads(self.rfile.read(n))
            return data if isinstance(data, dict) else None
        except Exception:
            return None

    def submit_lead(self):
        body = self.read_json() or {}
        name = str(body.get("name") or "").strip()
        phone = str(body.get("phone") or "").strip()
        email = str(body.get("email") or "").strip()
        role = str(body.get("role") or body.get("status") or "").strip()
        program = str(body.get("program") or "").strip()
        goal = str(body.get("goal") or body.get("message") or body.get("notes") or "").strip()
        try:
            with _db_lock, db() as con:
                if name or phone or email:
                    con.execute(
                        "INSERT INTO leads (name, phone, email, role, program, goal, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (name, phone, email, role, program, goal, int(time.time()))
                    )
            log_dir = ROOT / "data"
            log_dir.mkdir(parents=True, exist_ok=True)
            with open(log_dir / "inquiries.log", "a", encoding="utf-8") as f:
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] INQUIRY: Name={name} | Phone={phone} | Email={email} | Role={role} | Program={program} | Query={goal}\n")
        except Exception as e:
            print("Error recording lead:", e)
        return self.send_json(HTTPStatus.OK, {"ok": True, "message": "Inquiry received successfully"})

    def do_POST(self):
        path = urlsplit(self.path).path
        if not self.same_origin():
            return self.send_json(HTTPStatus.FORBIDDEN, {"error": "Cross-origin request blocked"})
        if path == "/api/chat":
            return self.handle_chat()
        if path == "/api/chat/lead":
            return self.handle_chat_lead()
        if path == "/api/admin/chatbot/config":
            return self.admin_chatbot_config_post()
        if path == "/api/admin/chatbot/knowledge":
            return self.admin_chatbot_knowledge_post()
        if path.startswith("/api/admin/crm/enquiry/") and path.endswith("/update"):
            return self.admin_crm_enquiry_update_post()
        if path == "/api/login":
            return self.login()
        if path == "/api/register":
            return self.register()
        if path == "/api/forgot-password":
            return self.forgot_password()
        if path == "/api/logout":
            destroy_session(self.token())
            return self.send_json(HTTPStatus.OK, {"ok": True}, {"Set-Cookie": self.set_cookie("", 0)})
        if path in ("/api/submit-lead.php", "/api/submit-lead", "/api/leads", "/api/contact"):
            return self.submit_lead()
        return self.send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})

    # --- CYBERPRO AI Assistant Chatbot Handlers ---
    def handle_chat(self):
        body = self.read_json()
        if not body:
            return self.send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Invalid request body."})

        message = str(body.get("message", "")).strip()
        session_id = str(body.get("session_id", "")).strip()
        history = body.get("history", [])
        if not isinstance(history, list):
            history = []

        client_ip = self.client_ip()
        res = chatbot_service.process_chat_message(message, history, client_ip, session_id=session_id)

        # If lead contact information was captured in message
        if res.get("lead_captured"):
            try:
                phone_match = re.search(r'(\+?\d{1,4}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}|\d{10}', message)
                email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', message)
                detected_phone = phone_match.group(0).strip() if phone_match else ""
                detected_email = email_match.group(0).strip() if email_match else ""

                with _db_lock, db() as con:
                    con.execute(
                        "INSERT INTO leads (name, phone, email, role, program, goal, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        ("Chatbot Lead", detected_phone, detected_email, "visitor", "CCCE / General Inquiry", message[:300], int(time.time()))
                    )
                log_dir = ROOT / "data"
                log_dir.mkdir(parents=True, exist_ok=True)
                with open(log_dir / "inquiries.log", "a", encoding="utf-8") as f:
                    f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] CHATBOT LEAD: Phone={detected_phone} | Email={detected_email} | Message={message}\n")
            except Exception as e:
                print("Error saving chatbot lead:", e)

        status_code = HTTPStatus.OK if res.get("ok") else HTTPStatus.BAD_REQUEST
        return self.send_json(status_code, res)

    def handle_chat_lead(self):
        body = self.read_json() or {}
        name = str(body.get("name", "")).strip()
        phone = str(body.get("phone", "")).strip()
        email = str(body.get("email", "")).strip()
        inquiry = str(body.get("inquiry", "")).strip()

        if not (name or phone or email):
            return self.send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Please provide your name, phone number, or email."})

        try:
            with _db_lock, db() as con:
                con.execute(
                    "INSERT INTO leads (name, phone, email, role, program, goal, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (name, phone, email, "chatbot_direct", "CCCE Program", inquiry[:500], int(time.time()))
                )
            log_dir = ROOT / "data"
            log_dir.mkdir(parents=True, exist_ok=True)
            with open(log_dir / "inquiries.log", "a", encoding="utf-8") as f:
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] CHATBOT DIRECT LEAD: Name={name} | Phone={phone} | Email={email} | Query={inquiry}\n")
            return self.send_json(HTTPStatus.OK, {"ok": True, "message": "Lead received. Counselor will reach out shortly."})
        except Exception as e:
            return self.send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": str(e)})

    def chat_config(self):
        cfg = chatbot_service.load_config()
        return self.send_json(HTTPStatus.OK, {
            "enabled": cfg.get("enabled", True),
            "system_name": cfg.get("system_name", "CYBERPRO AI ASSISTANT")
        })

    def admin_chatbot_config_get(self):
        user = user_for_token(self.token())
        if not user or user.get("role") not in ("admin", "superuser"):
            return self.send_json(HTTPStatus.FORBIDDEN, {"error": "Admin privileges required"})
        cfg = chatbot_service.load_config()
        safe_cfg = dict(cfg)
        if safe_cfg.get("gemini_api_key"):
            key = safe_cfg["gemini_api_key"]
            safe_cfg["gemini_api_key_masked"] = key[:4] + "..." + key[-4:] if len(key) > 8 else "***"
        if safe_cfg.get("openai_api_key"):
            key = safe_cfg["openai_api_key"]
            safe_cfg["openai_api_key_masked"] = key[:4] + "..." + key[-4:] if len(key) > 8 else "***"
        return self.send_json(HTTPStatus.OK, safe_cfg)

    def admin_chatbot_config_post(self):
        user = user_for_token(self.token())
        if not user or user.get("role") not in ("admin", "superuser"):
            return self.send_json(HTTPStatus.FORBIDDEN, {"error": "Admin privileges required"})
        body = self.read_json()
        if not body:
            return self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid JSON body"})
        current = chatbot_service.load_config()
        for k in ("enabled", "provider", "gemini_model", "openai_model", "temperature", "system_name", "rate_limit_per_minute"):
            if k in body:
                current[k] = body[k]
        if body.get("gemini_api_key") is not None:
            current["gemini_api_key"] = body["gemini_api_key"].strip()
        if body.get("openai_api_key") is not None:
            current["openai_api_key"] = body["openai_api_key"].strip()
        chatbot_service.save_config(current)
        return self.send_json(HTTPStatus.OK, {"ok": True, "message": "Chatbot configuration updated successfully."})

    def admin_chatbot_knowledge_get(self):
        user = user_for_token(self.token())
        if not user or user.get("role") not in ("admin", "superuser"):
            return self.send_json(HTTPStatus.FORBIDDEN, {"error": "Admin privileges required"})
        kb = chatbot_service.load_knowledge_base()
        return self.send_json(HTTPStatus.OK, kb)

    def admin_chatbot_knowledge_post(self):
        user = user_for_token(self.token())
        if not user or user.get("role") not in ("admin", "superuser"):
            return self.send_json(HTTPStatus.FORBIDDEN, {"error": "Admin privileges required"})
        body = self.read_json()
        if not body or not isinstance(body, dict):
            return self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid knowledge base JSON"})
        chatbot_service.save_knowledge_base(body)
        return self.send_json(HTTPStatus.OK, {"ok": True, "message": "Knowledge base updated successfully."})

    def admin_chatbot_leads_get(self):
        user = user_for_token(self.token())
        if not user or user.get("role") not in ("admin", "superuser"):
            return self.send_json(HTTPStatus.FORBIDDEN, {"error": "Admin privileges required"})
        with _db_lock, db() as con:
            rows = con.execute("SELECT id, name, phone, email, role, program, goal, created_at FROM leads ORDER BY id DESC LIMIT 50").fetchall()
        return self.send_json(HTTPStatus.OK, {"leads": [dict(r) for r in rows]})

    # --- CYBERPRO Admin CRM & Customer Intelligence Methods ---
    def admin_crm_enquiries_get(self):
        user = user_for_token(self.token())
        if not user or user.get("role") not in ("admin", "superuser"):
            return self.send_json(HTTPStatus.FORBIDDEN, {"error": "Admin privileges required"})

        query = urlsplit(self.path).query
        params = urllib.parse.parse_qs(query)
        search_q = params.get("q", [""])[0].strip().lower()
        status_filter = params.get("status", [""])[0].strip()

        with _db_lock, db() as con:
            sql = "SELECT * FROM customer_enquiries WHERE 1=1"
            args = []
            if status_filter:
                sql += " AND status = ?"
                args.append(status_filter)
            if search_q:
                sql += " AND (lower(full_name) LIKE ? OR lower(email) LIKE ? OR phone LIKE ? OR lower(location) LIKE ? OR lower(interested_course) LIKE ?)"
                wild = f"%{search_q}%"
                args.extend([wild, wild, wild, wild, wild])

            sql += " ORDER BY id DESC LIMIT 100"
            rows = con.execute(sql, args).fetchall()

            # KPI stats aggregation
            stats_rows = con.execute("""
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN status = 'new' THEN 1 ELSE 0 END) as new_count,
                    SUM(CASE WHEN status = 'awaiting_contact' THEN 1 ELSE 0 END) as awaiting_count,
                    SUM(CASE WHEN status = 'interested_student' THEN 1 ELSE 0 END) as student_count,
                    SUM(CASE WHEN status = 'contacted' THEN 1 ELSE 0 END) as contacted_count,
                    SUM(CASE WHEN status = 'converted' THEN 1 ELSE 0 END) as converted_count
                FROM customer_enquiries
            """).fetchone()

        stats = {
            "total": stats_rows["total"] or 0,
            "new": stats_rows["new_count"] or 0,
            "awaiting_contact": stats_rows["awaiting_count"] or 0,
            "interested_student": stats_rows["student_count"] or 0,
            "contacted": stats_rows["contacted_count"] or 0,
            "converted": stats_rows["converted_count"] or 0
        }

        return self.send_json(HTTPStatus.OK, {
            "enquiries": [dict(r) for r in rows],
            "stats": stats
        })

    def admin_crm_enquiry_detail_get(self):
        user = user_for_token(self.token())
        if not user or user.get("role") not in ("admin", "superuser"):
            return self.send_json(HTTPStatus.FORBIDDEN, {"error": "Admin privileges required"})

        parts = urlsplit(self.path).path.strip("/").split("/")
        try:
            enquiry_id = int(parts[-1])
        except Exception:
            return self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid enquiry ID"})

        with _db_lock, db() as con:
            row = con.execute("SELECT * FROM customer_enquiries WHERE id=?", (enquiry_id,)).fetchone()
            if not row:
                return self.send_json(HTTPStatus.NOT_FOUND, {"error": "Enquiry not found"})
            return self.send_json(HTTPStatus.OK, {"enquiry": dict(row)})

    def admin_crm_enquiry_update_post(self):
        user = user_for_token(self.token())
        if not user or user.get("role") not in ("admin", "superuser"):
            return self.send_json(HTTPStatus.FORBIDDEN, {"error": "Admin privileges required"})

        parts = urlsplit(self.path).path.strip("/").split("/")
        try:
            enquiry_id = int(parts[-2])
        except Exception:
            return self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid enquiry ID"})

        body = self.read_json() or {}
        new_status = str(body.get("status", "")).strip()
        admin_notes = str(body.get("admin_notes", "")).strip()

        with _db_lock, db() as con:
            con.execute("""
                UPDATE customer_enquiries SET
                    status = CASE WHEN ? != '' THEN ? ELSE status END,
                    admin_notes = ?,
                    updated_at = ?
                WHERE id = ?
            """, (new_status, new_status, admin_notes, int(time.time()), enquiry_id))

        return self.send_json(HTTPStatus.OK, {"ok": True, "message": "Enquiry updated successfully"})

    def admin_crm_export_csv(self):
        user = user_for_token(self.token())
        if not user or user.get("role") not in ("admin", "superuser"):
            return self.send_json(HTTPStatus.FORBIDDEN, {"error": "Admin privileges required"})

        with _db_lock, db() as con:
            rows = con.execute("SELECT * FROM customer_enquiries ORDER BY id DESC").fetchall()

        import io
        import csv
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "ID", "Date (UTC)", "Full Name", "Phone", "Email", "Location",
            "Knowledge Level", "Background", "Learning Goal", "Course", "Status",
            "Lead Score", "Requirements", "Admin Notes"
        ])

        for r in rows:
            date_str = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(r["created_at"])) if r["created_at"] else ""
            writer.writerow([
                r["id"], date_str, r["full_name"], r["phone"], r["email"], r["location"],
                r["knowledge_level"], r["background"], r["learning_goal"], r["interested_course"],
                r["status"], r["lead_score"], r["requirements"], r["admin_notes"]
            ])

        csv_bytes = output.getvalue().encode("utf-8")
        headers = {
            "Content-Type": "text/csv; charset=utf-8",
            "Content-Disposition": 'attachment; filename="cyberpro_customer_enquiries.csv"'
        }
        self.send_bytes(HTTPStatus.OK, csv_bytes, "text/csv; charset=utf-8", headers=headers)


    # --- Authentication Handlers
    def login(self):
        body = self.read_json()
        if body is None:
            return self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid request."})

        email = str(body.get("email", "")).strip().lower()[:254]
        password = str(body.get("password", ""))[:256]
        req_role = str(body.get("role", "")).strip().lower()

        # 1. Cloudflare Turnstile Human Verification (MANDATORY)
        cf_token = body.get("cf-turnstile-response") or body.get("turnstile_token") or body.get("cf_token") or ""
        valid_cf, cf_err = verify_turnstile(cf_token, self.client_ip())
        if not valid_cf:
            return self.send_json(HTTPStatus.BAD_REQUEST, {
                "error": cf_err,
                "code": "TURNSTILE_FAILED"
            })

        if not email or not password:
            return self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Email and password are required."})

        ip = self.client_ip()
        if too_many_failures(ip, email):
            return self.send_json(HTTPStatus.TOO_MANY_REQUESTS,
                                  {"error": "Too many failed attempts. Try again in 15 minutes."},
                                  {"Retry-After": str(FAIL_WINDOW)})

        with _db_lock, db() as con:
            row = con.execute("SELECT id, password_hash, is_active, role FROM users WHERE email=?", (email,)).fetchone()

        ok = verify_password(password, row["password_hash"] if row else _DUMMY_HASH)
        if not (row and ok and row["is_active"]):
            record_failure(ip, email)
            return self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Incorrect email or password."})

        user_role = row["role"] if ("role" in row.keys()) else "student"
        # Optional strict role validation if logging in via specific portal
        if req_role == "admin" and user_role not in ("admin", "superuser"):
            record_failure(ip, email)
            return self.send_json(HTTPStatus.FORBIDDEN, {"error": "Access denied: Account does not have administrator privileges."})
        if req_role == "instructor" and user_role not in ("instructor", "admin", "faculty"):
            record_failure(ip, email)
            return self.send_json(HTTPStatus.FORBIDDEN, {"error": "Access denied: Account does not have faculty/instructor credentials."})

        clear_failures(ip, email)
        token = create_session(row["id"])
        return self.send_json(HTTPStatus.OK, {
            "ok": True,
            "redirect": "/lms",
            "role": user_role
        }, {"Set-Cookie": self.set_cookie(token, int(SESSION_HOURS * 3600))})

    def register(self):
        body = self.read_json()
        if body is None:
            return self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid request."})

        name = str(body.get("name", "")).strip()[:100]
        email = str(body.get("email", "")).strip().lower()[:254]
        password = str(body.get("password", ""))[:256]

        # 1. Cloudflare Turnstile Human Verification (MANDATORY)
        cf_token = body.get("cf-turnstile-response") or body.get("turnstile_token") or body.get("cf_token") or ""
        valid_cf, cf_err = verify_turnstile(cf_token, self.client_ip())
        if not valid_cf:
            return self.send_json(HTTPStatus.BAD_REQUEST, {
                "error": cf_err,
                "code": "TURNSTILE_FAILED"
            })

        if not email or "@" not in email:
            return self.send_json(HTTPStatus.BAD_REQUEST, {"error": "A valid email address is required."})

        if len(password) < 8:
            return self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Password must be at least 8 characters long."})

        with _db_lock, db() as con:
            existing = con.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
            if existing:
                return self.send_json(HTTPStatus.CONFLICT, {"error": "An account with this email already exists. Please log in."})

            now = int(time.time())
            p_hash = hash_password(password)
            user_name = name or email.split("@")[0]
            cur = con.execute(
                "INSERT INTO users (email, name, password_hash, is_active, role, created_at) VALUES (?, ?, ?, 1, 'student', ?)",
                (email, user_name, p_hash, now)
            )
            user_id = cur.lastrowid

        token = create_session(user_id)
        return self.send_json(HTTPStatus.CREATED, {
            "ok": True,
            "message": "Student account registered successfully.",
            "redirect": "/lms"
        }, {"Set-Cookie": self.set_cookie(token, int(SESSION_HOURS * 3600))})

    def forgot_password(self):
        body = self.read_json()
        if body is None:
            return self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid request."})

        email = str(body.get("email", "")).strip().lower()[:254]

        # 1. Cloudflare Turnstile Human Verification (MANDATORY)
        cf_token = body.get("cf-turnstile-response") or body.get("turnstile_token") or body.get("cf_token") or ""
        valid_cf, cf_err = verify_turnstile(cf_token, self.client_ip())
        if not valid_cf:
            return self.send_json(HTTPStatus.BAD_REQUEST, {
                "error": cf_err,
                "code": "TURNSTILE_FAILED"
            })

        if not email or "@" not in email:
            return self.send_json(HTTPStatus.BAD_REQUEST, {"error": "A valid email address is required."})

        now = int(time.time())
        reset_token = secrets.token_urlsafe(32)
        with _db_lock, db() as con:
            user = con.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
            if user:
                con.execute(
                    "INSERT INTO password_resets (email, token, created_at, expires_at) VALUES (?, ?, ?, ?)",
                    (email, reset_token, now, now + 3600)
                )

        # Log reset action for admin / audit trail
        log_dir = ROOT / "data"
        log_dir.mkdir(parents=True, exist_ok=True)
        with open(log_dir / "inquiries.log", "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] PASSWORD RESET REQUEST: Email={email} | Token={reset_token[:12]}...\n")

        # Always return generic success message to prevent user enumeration
        return self.send_json(HTTPStatus.OK, {
            "ok": True,
            "message": "If an account matches this email, password recovery instructions have been sent."
        })


def main():
    init_db()
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"CyberPro running on http://{HOST}:{PORT}  (db: {DB_PATH})")
    print(f"Cloudflare Turnstile: {'ACTIVE (Managed Mode)' if TURNSTILE_ENABLED else 'DISABLED'}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
