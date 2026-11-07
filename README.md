# CYBERPRO — Zero-Trust Cybersecurity Defense Academy & LMS Platform

[![Security: Zero-Trust](https://img.shields.io/badge/Security-Zero--Trust-brightgreen.svg)]()
[![Bot Defense: Cloudflare Turnstile](https://img.shields.io/badge/Defense-Cloudflare%20Turnstile-orange.svg)]()
[![AI: Multi-Tier Inference](https://img.shields.io/badge/AI-Neural%20CRM%20Assistant-39ff14.svg)]()
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)]()

CYBERPRO is an enterprise-grade cybersecurity education, student learning management system (LMS), and lead intelligence platform featuring an interactive futuristic cybernetic visual theme, real Zero-Trust server-side authentication, Cloudflare Turnstile human verification, and a built-in AI Assistant with a full administrative CRM system.

---

## 1. System Architecture Overview

```
                      [ Website Visitors & Students ]
                                     │
                     ┌───────────────┴───────────────┐
                     ▼                               ▼
          Public Frontend Pages             Protected Applications
      (Home, CCCE, About, Programs)            (/lms, /admin/crm)
                     │                               │
                     │                               ▼
                     │                 Cloudflare Turnstile Defense
                     │                               │
                     │                 Session Token Validation
                     │                               │
                     └───────────────┬───────────────┘
                                     ▼
                           [ server.py Engine ]
                                     │
               ┌─────────────────────┼─────────────────────┐
               ▼                     ▼                     ▼
      [ Authentication API ] [ Chatbot & AI CRM ]   [ SQLite Data Store ]
      • Scrypt Passwords     • Multi-tier inference • users & sessions
      • Cookie Sessions      • Progressive discovery• customer_enquiries
      • Brute-force lockout  • Auto Lead Scoring    • course & progress
```

---

## 2. Key Platform Features

### A. Futuristic Cybernetic Frontend
- **Signature Cyber Theme**: Cybernetic Obsidian (`#070a08`), Neon Matrix Green (`#39ff14`), Cyan Laser Accents (`#00f5a0`), and Glassmorphic glow borders.
- **Interactive Visuals**:
  - Interactive 3D Cyber Guardian Robot head-turn animation tracked to cursor/touch coordinates (`public/assets/head_frames/`).
  - Holographic Tactical Radar canvas scanner with dual-frequency sweeps and active target blips.
  - Video scrub background player (`public/assets/cyberpro-guardian-video.mp4`).
  - Dynamic CCCE Flagship course curriculum cards (27 Modules, 180+ tools).

### B. Zero-Trust Security & Cloudflare Turnstile
- **Server-Side Bot Defense**: Integrates Cloudflare Turnstile managed bot challenge. Tokens are validated via `https://challenges.cloudflare.com/turnstile/v0/siteverify`.
- **Cryptographic Password Security**: Passwords hashed using Python standard library `hashlib.scrypt` with random 16-byte salts (no plain text ever stored).
- **Session Protection**: Encrypted random session tokens delivered exclusively in `HttpOnly; SameSite=Lax` cookies. Revoked immediately on server upon sign-out.
- **Brute-Force & Credential Stuffing Defense**: Automatic IP & account throttling with exponential backoff on consecutive failed attempts.
- **Zero Frontend Leakage**: The public bundle contains 0% LMS markup, no student data, and no administrative interfaces.

### C. Student Learning Management System (LMS)
- Located at `/lms` (authenticated via session cookie).
- Course player, module navigation, ethical hacking curriculum, video player, books/notes downloads, quiz modules, and student XP progress trackers.
- Role-based separation: dedicated portals for Students, Instructors, and Administrators.

### D. CYBERPRO AI Assistant & Administrative CRM
- **Floating AI Assistant Widget**: Resides in bottom-right corner across all public pages (`public/assets/cyber-chatbot.js` and `public/assets/cyber-chatbot.css`).
- **Dynamic Progressive Discovery**: Conversations feel natural; dynamically gathers visitor intent, education background, city, email, and phone without repeated questioning.
- **CRM Database Storage**: Inquiries are saved to `customer_enquiries` with conversation history JSON, requirements summary, and objective lead score (0-100).
- **Admin CRM Intelligence Dashboard** (`/admin/crm`):
  - Live KPI cards: Total, New, Interested Students, Awaiting Call, Contacted, Converted.
  - Real-time search across names, phone numbers, emails, and requirements.
  - Customer Dossier modal with full message transcript view, status editor, and counselor notes.
  - One-click WhatsApp link (`https://wa.me/<phone>`) to initiate counselor conversations.
  - Instant CSV export (`/api/admin/crm/export-csv`).

---

## 3. Directory Layout

```
CYBERPRO/
├── server.py                   # High-performance zero-trust HTTP server & API engine
├── chatbot_service.py          # AI Assistant, entity extraction, discovery & CRM sync
├── manage_users.py             # CLI utility for adding/managing admin & student accounts
├── requirements.txt            # Python dependencies (all standard library + optional LLMs)
├── package.json                # Project manifest for Emergent / Node runners
├── Procfile                    # Deployment entry point (web: python server.py)
├── Dockerfile                  # Container definition for containerized deployment
├── docker-compose.yml          # Local container composition
├── .env.example                # Safe environment variable configuration template
├── README.md                   # Comprehensive platform documentation
├── PROJECT-MIGRATION-GUIDE.md  # Step-by-step Emergent AI developer handover guide
│
├── data/                       # Database and configuration storage
│   ├── cyberpro.db             # Live SQLite database
│   ├── schema.sql              # Clean SQL dump of all tables, indexes, and seed data
│   ├── chatbot_config.json     # Multi-provider AI runtime configuration
│   └── cyberpro_knowledge.json # Official CYBERPRO curriculum and academy knowledge base
│
├── public/                     # Public web assets (Served statically)
│   ├── index.html              # Academy homepage with interactive hero, robot, & radar
│   ├── about.html              # About CYBERPRO, mission, founder Parth Rathod
│   ├── ccce.html               # CCCE Flagship 27-module master training syllabus
│   ├── programs.html           # Learning tracks and certification paths
│   ├── contact.html            # Admissions desk & institutional contact form
│   └── assets/                 # Styles, scripts, media, and 3D frames
│       ├── cyber-chatbot.js    # AI Assistant client widget & session persistence
│       ├── cyber-chatbot.css   # Obsidian glassmorphic neon chatbot styling
│       ├── motion.js           # Interactive animations and HUD telemetry
│       ├── site-auth.js        # Cloudflare Turnstile modal client handler
│       ├── cyberpro-guardian-video.mp4  # Visual guardian media
│       └── head_frames/        # 30 interactive robot rotation sequence frames
│
├── private/                    # Protected templates (Auth-gated, never served raw)
│   ├── lms.html                # Full student learning management system interface
│   └── admin-crm.html          # Administrative CRM lead intelligence dashboard
│
└── tests/                      # Automated test suites
    ├── test_crm.py             # CRM endpoints, lead lifecycle, CSV export & dossier tests
    ├── test_chatbot.py         # AI Assistant knowledge base & ethical guardrails tests
    ├── test_turnstile.py       # Cloudflare Turnstile bot verification & auth tests
    └── test_e2e_browser.py     # End-to-end browser user journey tests
```

---

## 4. Quick Start & Local Execution

### Prerequisites
- Python 3.10+ (Standard Library only; no third-party package installation required for core execution).

### Step 1: Initialize Environment
```bash
cp .env.example .env
```

### Step 2: Start CYBERPRO Platform
```bash
python server.py
```
The server will start listening at:
`http://127.0.0.1:8000/`

### Step 3: Access Default Portals & Accounts
The system includes initial pre-seeded administrative and student accounts:

| Portal | URL | Default Email | Default Password | Role |
| :--- | :--- | :--- | :--- | :--- |
| **Main Website** | `http://127.0.0.1:8000/` | *Public Access* | *N/A* | Visitor |
| **Student LMS** | `http://127.0.0.1:8000/lms` | `student@example.com` | `StudentPass@2026` | Student |
| **Founder Account** | `http://127.0.0.1:8000/lms` | `parthrathod122007@gmail.com` | `CyberPro@2026` | Superuser |
| **Admin CRM** | `http://127.0.0.1:8000/admin/crm` | `admin@cyberpro.com` | `CyberPro@2026` | Admin |

> **Note:** To create additional custom accounts via command line:
> ```bash
> python manage_users.py add newuser@cyberpro.com --name "Analyst Name" --role admin
> ```

---

## 5. Running Automated Verification Tests

The platform contains complete unit and integration test suites:

```bash
# 1. Run CRM & Lead Management Tests (6/6 tests)
python -m unittest tests/test_crm.py

# 2. Run Chatbot & Knowledge Base Tests (7/7 tests)
python -m unittest tests/test_chatbot.py

# 3. Run Turnstile Bot Defense & Security Tests (11/11 tests)
python -m unittest tests/test_turnstile.py
```

---

## 6. Cloud & Production Deployment

1. **HTTPS Enforcement**: When deploying behind a production domain with SSL/TLS (e.g. Cloudflare, Nginx, Caddy), set:
   ```env
   CYBERPRO_COOKIE_SECURE=1
   CYBERPRO_TRUST_PROXY=1
   CYBERPRO_HOST=0.0.0.0
   ```
2. **Cloudflare Turnstile**:
   Replace the default development test keys in `.env` with your real keys from the [Cloudflare Turnstile Dashboard](https://dash.cloudflare.com/?to=/:account/turnstile).
3. **Database Persistence**:
   Ensure the `data/` directory is mapped to a persistent volume so that `cyberpro.db` persists across container restarts.

---

## 7. Founder & Support Contact

- **Founder & Director**: Parth Rathod
- **Official Admissions WhatsApp**: [+91 76668762325](https://wa.me/9176668762325)
- **Official Support Email**: `support@cyberpro.com`
- **Platform Version**: 2.0.0 (Production Stable)
