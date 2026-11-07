"""
CYBERPRO AI ASSISTANT - CRM & CONVERSATIONAL INTELLIGENCE SERVICE
Intelligent Customer Profiling, Multi-Turn State Machine & Lead Management
Supports:
  1. Automated Entity & Intent Extraction (Name, Phone, Email, Location, Level, Background, Goal)
  2. Multi-Turn Adaptive Question & Answer Progression (Never interrogates, never repeats)
  3. Dynamic Lead Scoring & CRM Database Synchronization
  4. Google Gemini API / OpenAI API / Built-In CYBERPRO Neural Inference Engine
"""

import json
import os
import re
import time
import sqlite3
import urllib.request
import urllib.error
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
DB_PATH = DATA_DIR / "cyberpro.db"
KNOWLEDGE_FILE = DATA_DIR / "cyberpro_knowledge.json"
CONFIG_FILE = DATA_DIR / "chatbot_config.json"

_rate_limits: Dict[str, List[float]] = {}


def get_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    return con


def load_knowledge_base() -> Dict[str, Any]:
    try:
        if KNOWLEDGE_FILE.is_file():
            with open(KNOWLEDGE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        print("Error loading knowledge base:", e)
    return {}


def load_config() -> Dict[str, Any]:
    defaults = {
        "enabled": True,
        "provider": "auto",
        "gemini_api_key": os.environ.get("GEMINI_API_KEY", ""),
        "gemini_model": os.environ.get("GEMINI_MODEL", "gemini-1.5-flash"),
        "openai_api_key": os.environ.get("OPENAI_API_KEY", ""),
        "openai_model": os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
        "temperature": 0.4,
        "max_tokens": 1000,
        "system_name": "CYBERPRO AI ASSISTANT",
        "rate_limit_per_minute": 25,
        "max_input_length": 1500
    }
    try:
        if CONFIG_FILE.is_file():
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg = json.load(f)
                defaults.update(cfg)
                if os.environ.get("GEMINI_API_KEY"):
                    defaults["gemini_api_key"] = os.environ["GEMINI_API_KEY"]
                if os.environ.get("OPENAI_API_KEY"):
                    defaults["openai_api_key"] = os.environ["OPENAI_API_KEY"]
    except Exception as e:
        print("Error loading chatbot config:", e)
    return defaults


def save_config(new_config: Dict[str, Any]) -> bool:
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(new_config, f, indent=2)
        return True
    except Exception as e:
        print("Error saving chatbot config:", e)
        return False


def save_knowledge_base(new_kb: Dict[str, Any]) -> bool:
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        with open(KNOWLEDGE_FILE, "w", encoding="utf-8") as f:
            json.dump(new_kb, f, indent=2)
        return True
    except Exception as e:
        print("Error saving knowledge base:", e)
        return False


def is_rate_limited(ip: str, limit: int = 25, window: float = 60.0) -> bool:
    now = time.time()
    timestamps = _rate_limits.get(ip, [])
    timestamps = [t for t in timestamps if now - t < window]
    if len(timestamps) >= limit:
        _rate_limits[ip] = timestamps
        return True
    timestamps.append(now)
    _rate_limits[ip] = timestamps
    return False


def sanitize_input(text: str, max_len: int = 1500) -> str:
    if not text:
        return ""
    clean = text.strip()[:max_len]
    clean = re.sub(r'(?i)(ignore all previous instructions|bypass system prompt|disregard prior rules)', '[SECURITY FILTERED]', clean)
    return clean


# -----------------------------------------------------------------------------
# CRM ENTITY EXTRACTION & CUSTOMER PROFILING
# -----------------------------------------------------------------------------

def extract_customer_entities(message: str, existing_profile: Dict[str, Any]) -> Dict[str, Any]:
    """
    Intelligently extracts customer information from natural conversation text
    and updates their progressive profile.
    """
    profile = dict(existing_profile)
    text = message.strip()
    low = text.lower()

    # 1. Email extraction
    email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', text)
    if email_match and not profile.get("email"):
        profile["email"] = email_match.group(0).lower().strip()

    # 2. Phone / WhatsApp extraction (10-14 digits, optional + or country code)
    phone_match = re.search(r'(\+?\d{1,4}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}|\b\d{10}\b', text)
    if phone_match and not profile.get("phone"):
        raw_phone = phone_match.group(0).strip()
        # Ensure it looks like a valid phone number, not a year or count
        if len(re.sub(r'\D', '', raw_phone)) >= 10:
            profile["phone"] = raw_phone

    # 3. Name extraction
    if not profile.get("full_name") or profile.get("full_name") in ("Visitor", ""):
        name_patterns = [
            r'(?:my name is|i am|i\'m|this is|call me)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)',
            r'(?:name\s*[:=-]\s*)([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)',
            r'^([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\s+(?:here|from|and\s+my\s+phone)',
        ]
        for pat in name_patterns:
            m = re.search(pat, text, re.IGNORECASE)
            if m:
                cand = m.group(1).strip()
                # Exclude false positives like "I am a student"
                if cand.lower() not in ("a student", "a beginner", "interested", "looking", "new", "working", "trying"):
                    profile["full_name"] = cand.title()
                    break

    # 4. Location extraction
    if not profile.get("location"):
        loc_patterns = [
            r'(?:from|in|living in|located in|based in)\s+([A-Za-z]+(?:\s+[A-Za-z]+)?)(?:,|\.|\s|$)',
        ]
        for pat in loc_patterns:
            m = re.search(pat, text, re.IGNORECASE)
            if m:
                cand = m.group(1).strip()
                if cand.lower() not in ("cybersecurity", "scratch", "beginning", "college", "school", "office", "home", "india", "usa"):
                    profile["location"] = cand.title()
                    break

    # 5. Knowledge Level detection
    if not profile.get("knowledge_level"):
        if any(k in low for k in ["beginner", "zero knowledge", "no coding", "new to cyber", "fresher", "start from scratch", "basic"]):
            profile["knowledge_level"] = "Beginner"
        elif any(k in low for k in ["intermediate", "know some networking", "ceh", "learning for 6 months", "moderate"]):
            profile["knowledge_level"] = "Intermediate"
        elif any(k in low for k in ["experienced", "working in soc", "penetration tester", "security analyst", "advanced"]):
            profile["knowledge_level"] = "Experienced"

    # 6. Background detection
    if not profile.get("background"):
        if any(k in low for k in ["college student", "university", "btech", "bca", "mtech", "student", "final year", "engineering"]):
            profile["background"] = "College Student"
        elif any(k in low for k in ["working professional", "working in it", "software engineer", "sysadmin", "it support", "developer"]):
            profile["background"] = "Working Professional"
        elif any(k in low for k in ["switch career", "non-it", "different field", "career changer", "transition"]):
            profile["background"] = "Career Switcher"
        elif any(k in low for k in ["self-taught", "independent", "freelancer", "hobbyist"]):
            profile["background"] = "Independent Learner"

    # 7. Learning Goal detection
    if not profile.get("learning_goal"):
        if any(k in low for k in ["job", "placement", "career", "get hired", "interview"]):
            profile["learning_goal"] = "Career & Placement"
        elif any(k in low for k in ["certificate", "certified", "exam", "certification"]):
            profile["learning_goal"] = "Certification"
        elif any(k in low for k in ["practical skills", "hands on", "learn tools", "offensive security", "bug bounty"]):
            profile["learning_goal"] = "Practical Skills & Bug Bounty"

    # 8. Interested Course / Track
    if not profile.get("interested_course") or profile.get("interested_course") == "General":
        if any(k in low for k in ["ccce", "flagship", "6 month", "certified cybersecurity expert"]):
            profile["interested_course"] = "CCCE Flagship Program"
        elif any(k in low for k in ["ethical hacking", "penetration testing", "red team", "bug bounty"]):
            profile["interested_course"] = "Ethical Hacking & Pentesting"
        elif any(k in low for k in ["soc", "blue team", "security operations", "splunk", "incident response"]):
            profile["interested_course"] = "SOC Analyst & Blue Team"
        elif any(k in low for k in ["corporate", "enterprise", "workforce", "training for team"]):
            profile["interested_course"] = "Corporate Training"

    # 9. Preferred Schedule
    if not profile.get("preferred_schedule"):
        if "weekend" in low:
            profile["preferred_schedule"] = "Weekend Batch"
        elif any(k in low for k in ["evening", "after office", "night"]):
            profile["preferred_schedule"] = "Evening Batch"

    # Update requirements notes if message has substantial user query
    if len(text) > 15 and not profile.get("requirements"):
        profile["requirements"] = text[:300]
    elif len(text) > 15 and profile.get("requirements") and text not in profile["requirements"]:
        profile["requirements"] = (profile["requirements"] + " | " + text[:150])[:500]

    return profile


def calculate_lead_score(profile: Dict[str, Any]) -> int:
    score = 30
    if profile.get("phone"):
        score += 25
    if profile.get("email"):
        score += 15
    if profile.get("full_name") and profile.get("full_name") != "Visitor":
        score += 10
    if profile.get("knowledge_level"):
        score += 5
    if profile.get("background"):
        score += 5
    if profile.get("learning_goal"):
        score += 5
    if profile.get("interested_course") and "CCCE" in profile.get("interested_course", ""):
        score += 5
    return min(100, score)


# -----------------------------------------------------------------------------
# DATABASE CRM SYNCHRONIZATION
# -----------------------------------------------------------------------------

def sync_crm_lead(session_id: str, profile: Dict[str, Any], history: List[Dict[str, str]]) -> Dict[str, Any]:
    """
    Saves or updates the customer enquiry record in SQLite.
    Performs automatic deduplication by email or phone.
    """
    now = int(time.time())
    score = calculate_lead_score(profile)
    profile["lead_score"] = score

    email = (profile.get("email") or "").strip().lower()
    phone = (profile.get("phone") or "").strip()
    name = (profile.get("full_name") or "Visitor").strip()

    # Determine status
    current_status = profile.get("status", "new")
    if phone or "call" in profile.get("requirements", "").lower() or "whatsapp" in profile.get("requirements", "").lower():
        if current_status == "new":
            current_status = "awaiting_contact"
    if profile.get("background") == "College Student" and current_status == "new":
        current_status = "interested_student"
    profile["status"] = current_status

    # Generate multi-sentence summary
    summary_parts = []
    if name != "Visitor":
        summary_parts.append(f"Customer: {name}")
    if profile.get("location"):
        summary_parts.append(f"Location: {profile['location']}")
    if profile.get("knowledge_level"):
        summary_parts.append(f"Level: {profile['knowledge_level']}")
    if profile.get("background"):
        summary_parts.append(f"Background: {profile['background']}")
    if profile.get("learning_goal"):
        summary_parts.append(f"Goal: {profile['learning_goal']}")
    if profile.get("interested_course"):
        summary_parts.append(f"Interest: {profile['interested_course']}")
    if profile.get("preferred_schedule"):
        summary_parts.append(f"Schedule: {profile['preferred_schedule']}")
    summary = " | ".join(summary_parts) if summary_parts else "General inquiry"
    profile["conversation_summary"] = summary

    history_json = json.dumps(history[-16:])

    with get_db() as con:
        # Check if record already exists by session_id, or by email, or by phone
        row = None
        if email:
            row = con.execute("SELECT id FROM customer_enquiries WHERE email=? AND email != ''", (email,)).fetchone()
        if not row and phone:
            row = con.execute("SELECT id FROM customer_enquiries WHERE phone=? AND phone != ''", (phone,)).fetchone()
        if not row and session_id:
            row = con.execute("SELECT id FROM customer_enquiries WHERE session_id=?", (session_id,)).fetchone()

        if row:
            enquiry_id = row["id"]
            con.execute("""
                UPDATE customer_enquiries SET
                    full_name = CASE WHEN ? != 'Visitor' AND ? != '' THEN ? ELSE full_name END,
                    email = CASE WHEN ? != '' THEN ? ELSE email END,
                    phone = CASE WHEN ? != '' THEN ? ELSE phone END,
                    location = CASE WHEN ? != '' THEN ? ELSE location END,
                    interested_course = CASE WHEN ? != '' THEN ? ELSE interested_course END,
                    knowledge_level = CASE WHEN ? != '' THEN ? ELSE knowledge_level END,
                    background = CASE WHEN ? != '' THEN ? ELSE background END,
                    learning_goal = CASE WHEN ? != '' THEN ? ELSE learning_goal END,
                    preferred_schedule = CASE WHEN ? != '' THEN ? ELSE preferred_schedule END,
                    requirements = ?,
                    conversation_summary = ?,
                    conversation_history = ?,
                    status = ?,
                    lead_score = ?,
                    updated_at = ?
                WHERE id = ?
            """, (
                name, name, name,
                email, email,
                phone, phone,
                profile.get("location", ""), profile.get("location", ""),
                profile.get("interested_course", ""), profile.get("interested_course", ""),
                profile.get("knowledge_level", ""), profile.get("knowledge_level", ""),
                profile.get("background", ""), profile.get("background", ""),
                profile.get("learning_goal", ""), profile.get("learning_goal", ""),
                profile.get("preferred_schedule", ""), profile.get("preferred_schedule", ""),
                profile.get("requirements", ""),
                summary,
                history_json,
                current_status,
                score,
                now,
                enquiry_id
            ))
            profile["id"] = enquiry_id
        else:
            cur = con.execute("""
                INSERT INTO customer_enquiries (
                    session_id, full_name, email, phone, location,
                    interested_course, knowledge_level, background, learning_goal,
                    preferred_schedule, requirements, conversation_summary,
                    conversation_history, status, lead_score, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                session_id, name, email, phone, profile.get("location", ""),
                profile.get("interested_course", "CCCE Flagship"), profile.get("knowledge_level", ""),
                profile.get("background", ""), profile.get("learning_goal", ""),
                profile.get("preferred_schedule", ""), profile.get("requirements", ""),
                summary, history_json, current_status, score, now, now
            ))
            profile["id"] = cur.lastrowid

        # Also sync to legacy leads table for backward compatibility
        if (email or phone) and (name != "Visitor"):
            con.execute("""
                INSERT OR IGNORE INTO leads (name, phone, email, goal, role, program, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                name, phone, email, profile.get("requirements", "")[:300],
                profile.get("background", "student"), profile.get("interested_course", "CCCE"), now
            ))

    return profile


# -----------------------------------------------------------------------------
# ADAPTIVE MULTI-TURN CONVERSATION PROGRESSION
# -----------------------------------------------------------------------------

def determine_next_follow_up(profile: Dict[str, Any], user_msg: str) -> Optional[str]:
    """
    Intelligently inspects what information has already been collected,
    and returns the next logical, friendly question to continue the conversation.
    Avoids asking questions already answered.
    """
    low = user_msg.lower()

    # If the user just gave contact details, thank them and do not ask another question immediately
    if bool(re.search(r'[\w\.-]+@[\w\.-]+\.\w+', user_msg)) or bool(re.search(r'(\+?\d{1,4}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}|\b\d{10}\b', user_msg)):
        return None

    # Step 1: Knowledge level discovery
    if not profile.get("knowledge_level"):
        if any(k in low for k in ["learn", "ethical hacking", "course", "ccce", "start", "join", "study"]):
            return "Are you completely new to cybersecurity, or do you already have some technical or networking background?"

    # Step 2: Background discovery
    if not profile.get("background"):
        if profile.get("knowledge_level") or any(k in low for k in ["beginner", "zero", "experienced", "intermediate"]):
            return "Are you currently a college student, working professional, or looking to switch careers into tech?"

    # Step 3: Main learning goal
    if not profile.get("learning_goal"):
        if profile.get("background") or any(k in low for k in ["student", "working", "engineer", "college"]):
            return "What is your primary goal—are you preparing for job placements, building practical hands-on skills, or aiming for international certifications?"

    # Step 4: Schedule preference or admissions handover with consent
    if not profile.get("preferred_schedule") and any(k in low for k in ["batch", "timing", "schedule", "when", "class", "enroll", "fee", "cost"]):
        return "We offer flexible evening and weekend batches for CCCE Live Cohort 03. Which schedule works best for your routine?"

    # Step 5: Contact collection with explicit value & consent
    if not (profile.get("phone") or profile.get("email")):
        if any(k in low for k in ["enroll", "syllabus", "admission", "register", "join", "brochure", "fee", "cost", "human", "call", "whatsapp"]):
            return "Our admissions counselor Parth Rathod can share the complete 27-module syllabus PDF, batch schedule, and scholarship options. What is your name and WhatsApp number so we can send that over to you?"

    return None


def build_system_prompt(kb: Dict[str, Any], profile: Dict[str, Any]) -> str:
    company = kb.get("company", {})
    contact = kb.get("contact", {})
    phone = contact.get("phone", "+91 76668762325")

    known_facts = []
    if profile.get("full_name") and profile["full_name"] != "Visitor":
        known_facts.append(f"Customer Name: {profile['full_name']}")
    if profile.get("knowledge_level"):
        known_facts.append(f"Skill Level: {profile['knowledge_level']}")
    if profile.get("background"):
        known_facts.append(f"Background: {profile['background']}")
    if profile.get("learning_goal"):
        known_facts.append(f"Learning Goal: {profile['learning_goal']}")
    if profile.get("location"):
        known_facts.append(f"Location: {profile['location']}")
    if profile.get("phone"):
        known_facts.append(f"WhatsApp/Phone: {profile['phone']}")
    if profile.get("email"):
        known_facts.append(f"Email: {profile['email']}")

    profile_context = "\n".join(known_facts) if known_facts else "No prior details known yet."

    prompt = f"""You are the official CYBERPRO AI ASSISTANT, representing CYBERPRO Defense Academy.
Founder & Owner: {company.get('founder_and_owner', 'Parth Rathod')}.
Official Contact / WhatsApp Admissions: {phone}.
Official Support Email: {contact.get('support_email', 'support@cyberpro.com')}.

CONVERSATION & LEAD INTELLIGENCE OBJECTIVES:
1. Act like a senior, friendly CYBERPRO customer-support representative and course advisor.
2. Communicate naturally, empathetically, and knowledgeably.
3. Understand what the visitor needs and provide clear, structured cybersecurity answers.
4. Intelligently ask relevant progressive discovery questions, weave them naturally into your response, and NEVER interrogate.
5. REMEMBER what the visitor already told you. NEVER ask for information they have already provided!

CURRENT CUSTOMER PROFILE KNOWN:
{profile_context}

OFFICIAL CYBERPRO FACTS:
• Flagship: CCCE (CyberPro Certified Cybersecurity Expert).
• 6 Months live practical training, 27 modules, 180+ tools (Wireshark, Burp Suite, Nmap, Metasploit, Splunk, Ghidra, Kali Linux, etc.).
• Live classes with recordings in Student LMS (/lms), guided cloud labs, 1-on-1 mentor reviews, capstone projects, verified certificate.
• Current batch: Live Cohort 03 enrolling now (flexible evening & weekend options).
• Tuition: Never invent fake numeric fees; explain scholarship & installment options and invite them to connect on WhatsApp ({phone}).
• Ethics: Strictly defensive, educational cybersecurity only. Decline any illegal hacking requests politely.
"""
    return prompt


# -----------------------------------------------------------------------------
# TIER 1: External AI API Integrations (Gemini / OpenAI)
# -----------------------------------------------------------------------------

def call_gemini_api(api_key: str, model: str, system_prompt: str, history: List[Dict[str, str]], user_msg: str) -> Tuple[bool, str]:
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    contents = []
    for h in history[-8:]:
        role = "user" if h.get("role") == "user" else "model"
        text = h.get("content", "")
        if text:
            contents.append({"role": role, "parts": [{"text": text}]})
    contents.append({"role": "user", "parts": [{"text": user_msg}]})

    payload = {
        "systemInstruction": {"parts": [{"text": system_prompt}]},
        "contents": contents,
        "generationConfig": {"temperature": 0.45, "maxOutputTokens": 1000, "topP": 0.95}
    }

    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=12) as res:
            res_data = json.loads(res.read().decode("utf-8"))
            candidates = res_data.get("candidates", [])
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                if parts:
                    return True, parts[0].get("text", "")
            return False, "Empty response from Gemini."
    except Exception as e:
        return False, f"Gemini API error: {str(e)}"


def call_openai_api(api_key: str, model: str, system_prompt: str, history: List[Dict[str, str]], user_msg: str) -> Tuple[bool, str]:
    url = "https://api.openai.com/v1/chat/completions"
    messages = [{"role": "system", "content": system_prompt}]
    for h in history[-8:]:
        role = "user" if h.get("role") == "user" else "assistant"
        text = h.get("content", "")
        if text:
            messages.append({"role": role, "content": text})
    messages.append({"role": "user", "content": user_msg})

    payload = {
        "model": model,
        "messages": messages,
        "temperature": 0.45,
        "max_tokens": 1000
    }

    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=12) as res:
            res_data = json.loads(res.read().decode("utf-8"))
            choices = res_data.get("choices", [])
            if choices:
                return True, choices[0].get("message", {}).get("content", "")
            return False, "Empty response from OpenAI."
    except Exception as e:
        return False, f"OpenAI API error: {str(e)}"


# -----------------------------------------------------------------------------
# TIER 2: Built-in CYBERPRO Neural Inference Engine (Context-Aware State Machine)
# -----------------------------------------------------------------------------

def built_in_inference_engine(user_msg: str, history: List[Dict[str, str]], kb: Dict[str, Any], profile: Dict[str, Any]) -> str:
    msg = user_msg.lower().strip()
    contact = kb.get("contact", {})
    phone = contact.get("phone", "+91 76668762325")
    wa_url = contact.get("whatsapp_chat_url", f"https://wa.me/{phone.replace('+', '').replace(' ', '')}")

    # Check for next follow-up question
    next_question = determine_next_follow_up(profile, user_msg)
    follow_up_suffix = f"\n\n**Quick question:** {next_question}" if next_question else ""

    # 1. Lead / Contact Details Provided (Name, Phone, Email)
    has_email = bool(re.search(r'[\w\.-]+@[\w\.-]+\.\w+', user_msg))
    has_phone = bool(re.search(r'(\+?\d{1,4}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}|\b\d{10}\b', user_msg))
    if has_email or has_phone:
        name_str = f" {profile['full_name']}" if profile.get("full_name") and profile["full_name"] != "Visitor" else ""
        return (
            f"Thank you{name_str}! 🛡️ Your details have been securely recorded in our admissions system.\n\n"
            f"Our senior counselor Parth Rathod and admissions desk will reach out to you directly on WhatsApp ({profile.get('phone', phone)}) "
            f"with the complete **CCCE syllabus PDF**, current cohort batch schedule, and scholarship fee breakdown.\n\n"
            f"If you'd like an immediate response, you can also start a direct WhatsApp chat with us right now: **[{phone}]({wa_url})**."
        )

    # 2. Human Handover Request
    if any(k in msg for k in ["talk to human", "speak to real person", "real person", "call me", "speak to advisor", "speak to counselor"]):
        if profile.get("phone") or profile.get("email"):
            return (
                f"I've alerted our admissions desk for you! 📞\n\n"
                f"A team member will contact you on WhatsApp/phone at **{profile.get('phone', phone)}**.\n\n"
                f"You can also chat directly with our founder Parth Rathod on WhatsApp right here: **[{phone}]({wa_url})**."
            )
        else:
            return (
                "I'd be happy to arrange that! 📞\n\n"
                "May I have your **name** and **WhatsApp number** so our CYBERPRO admissions team can connect with you directly?"
            )

    # 3. Ethical / Illegal Hacking Guardrail
    illegal_triggers = ["hack wifi", "hack instagram", "hack facebook", "hack whatsapp", "ddos script", "steal password", "crack account", "bypass otp"]
    if any(trigger in msg for trigger in illegal_triggers):
        return (
            "**Notice:** CYBERPRO Defense Academy strictly adheres to ethical hacking, authorized security testing, and legal compliance.\n\n"
            "We do **not** assist with unauthorized penetration or malicious attacks against personal accounts.\n\n"
            "Instead, we train you in **defensive security, vulnerability remediation, and authorized penetration testing** to legally protect systems and earn industry certifications.\n\n"
            "Would you like to explore how our **CCCE program** prepares you for legitimate ethical hacking and SOC analyst careers?"
        )

    # 4. What is CYBERPRO / Founder Info
    if any(k in msg for k in ["what is cyberpro", "who is parth", "parth rathod", "about cyberpro", "founder", "about company"]):
        return (
            "**Welcome to CYBERPRO Defense Academy!** 🛡️\n\n"
            "CYBERPRO was founded by **Parth Rathod** to provide structured, practical cybersecurity training centered around enterprise labs, live mentorship, and real defense capabilities.\n\n"
            "• **Live Guided Labs:** 180+ industry tools and simulated corporate environments.\n"
            "• **Flagship CCCE:** 6 Months of live training across 27 comprehensive modules.\n"
            "• **Student LMS:** Lifetime access to video archives, tools, notes, and quizzes.\n"
            "• **Career Guidance:** Real portfolio capstone audits and verified cryptographic certification."
            + follow_up_suffix
        )

    # 5. Course Offerings / What Courses
    if any(k in msg for k in ["what course", "which course", "all courses", "courses offer", "programs"]):
        return (
            "**CYBERPRO Training Programs & Pathways:** 🎯\n\n"
            "Our flagship and most comprehensive pathway is the **CCCE (CyberPro Certified Cybersecurity Expert)** program:\n\n"
            "1. **Foundations (Level 1):** Networking architecture (TCP/IP, OSI), Linux terminal, Bash scripting, and SOC 101.\n"
            "2. **Offensive & Defensive Labs (Level 2):** Web Pentesting (OWASP Top 10), Network Security, Cryptography, and Vulnerability Assessment.\n"
            "3. **Enterprise Defense (Level 3):** Red Teaming, Active Directory attacks, Incident Response, and Cloud Security."
            + follow_up_suffix
        )

    # 6. CCCE Program Specifics / Modules / Tools
    if any(k in msg for k in ["ccce", "modules", "tools", "duration", "how long"]):
        return (
            "**CyberPro Certified Cybersecurity Expert (CCCE):** 🚀\n\n"
            "• **Duration:** 6 Months Live Practical Training\n"
            "• **Curriculum:** 27 Deep-Dive Technical Modules\n"
            "• **Tools Covered:** 180+ Enterprise Tools (Wireshark, Burp Suite, Nmap, Metasploit, Splunk SIEM, Ghidra, Kali Linux)\n"
            "• **Live Batches:** Live Cohort 03 is currently enrolling with evening and weekend schedule options.\n"
            "• **Certification:** Verified CCCE Credential with online cryptographic verification ID."
            + follow_up_suffix
        )

    # 7. Beginner / How to start
    if any(k in msg for k in ["learn ethical hacking", "how to start", "beginner", "no coding", "zero background", "start"]):
        return (
            "**Starting from Scratch with CYBERPRO:** 💡\n\n"
            "You do not need any coding or prior hacking background to begin. Our curriculum follows a progressive 4-phase ladder:\n\n"
            "1. **Foundations First:** Master networking protocols (TCP/IP, DNS, HTTP) and Linux terminal command line.\n"
            "2. **Security Tools:** Learn industry tools in safe, pre-configured cloud sandbox environments.\n"
            "3. **Attack & Defense:** Perform real-world guided vulnerability assessments and web exploitation.\n"
            "4. **Executive Capstone:** Complete a simulated enterprise infrastructure penetration audit."
            + follow_up_suffix
        )

    # 8. Fees / Pricing / Scholarship / Installments
    if any(k in msg for k in ["fee", "fees", "cost", "price", "how much", "pricing", "scholarship", "installment", "emi"]):
        return (
            "**CYBERPRO Fee & Scholarship Structure:** 💳\n\n"
            "Program fees are tailored to student backgrounds and cohort schedules:\n\n"
            "• **Scholarships:** Early-bird and merit-based scholarship fee reductions are available for upcoming Live Cohort 03 batches.\n"
            "• **Flexible Payments:** We provide interest-free monthly installment (EMI) plans.\n\n"
            f"Because fees vary depending on your track and scholarship qualification, our admissions desk shares the transparent fee sheet directly on WhatsApp at **[{phone}]({wa_url})**."
            + follow_up_suffix
        )

    # 9. Student LMS Access
    if any(k in msg for k in ["lms", "login", "student portal", "dashboard", "portal", "password"]):
        return (
            "**CYBERPRO Student LMS Guide:** 💻\n\n"
            "• **Access Link:** Click the **STUDENT LMS** button on the navbar, or go to [/lms](/lms).\n"
            "• **How to Login:** Choose 'Student Login' or 'Admin', enter your registered email and password, complete Cloudflare verification, and sign in.\n"
            "• **Features:** Recorded video library, tools downloads, live class links, quizzes, and digital certificates."
            + follow_up_suffix
        )

    # 10. Default Contextual Fallback
    return (
        "Welcome to **CYBERPRO Defense Academy**! 🛡️\n\n"
        "We specialize in practical cybersecurity training, live lab mentorship, and our flagship **CCCE** program (6 Months, 27 Modules, 180+ tools).\n\n"
        "How can I best assist you today? I can help you explore our curriculum, guide your learning path, assist with the Student LMS, or connect you with admissions."
        + follow_up_suffix
    )


# -----------------------------------------------------------------------------
# MASTER CHAT DISPATCHER WITH CRM SYNCHRONIZATION
# -----------------------------------------------------------------------------

def process_chat_message(user_msg: str, history: List[Dict[str, str]], client_ip: str, session_id: str = "") -> Dict[str, Any]:
    cfg = load_config()

    if not cfg.get("enabled", True):
        return {
            "ok": False,
            "error": "The CYBERPRO AI Assistant is temporarily undergoing routine maintenance. Please contact admissions on WhatsApp at +91 76668762325.",
            "status": "maintenance"
        }

    # 1. Rate Limiting Check
    rate_limit = int(cfg.get("rate_limit_per_minute", 25))
    if is_rate_limited(client_ip, limit=rate_limit):
        return {
            "ok": False,
            "error": "You are sending messages too quickly. Please pause for a few seconds before trying again.",
            "status": "rate_limited"
        }

    # 2. Input Sanitization
    max_len = int(cfg.get("max_input_length", 1500))
    clean_msg = sanitize_input(user_msg, max_len)
    if not clean_msg:
        return {
            "ok": False,
            "error": "Message cannot be empty.",
            "status": "empty_input"
        }

    # 3. Load or Retrieve Customer CRM Profile
    profile = {}
    if session_id:
        with get_db() as con:
            row = con.execute("SELECT * FROM customer_enquiries WHERE session_id=?", (session_id,)).fetchone()
            if row:
                profile = dict(row)

    # 4. Extract Entities & Progressive Profiling
    profile = extract_customer_entities(clean_msg, profile)

    kb = load_knowledge_base()
    system_prompt = build_system_prompt(kb, profile)

    provider = cfg.get("provider", "auto").lower()
    gemini_key = cfg.get("gemini_api_key", "").strip()
    openai_key = cfg.get("openai_api_key", "").strip()

    reply_text = ""
    used_provider = "built-in"

    # Attempt Gemini API if configured
    if (provider in ("auto", "gemini")) and gemini_key:
        model = cfg.get("gemini_model", "gemini-1.5-flash")
        success, res = call_gemini_api(gemini_key, model, system_prompt, history, clean_msg)
        if success and res.strip():
            reply_text = res.strip()
            used_provider = f"gemini ({model})"

    # Attempt OpenAI API if configured
    if not reply_text and (provider in ("auto", "openai")) and openai_key:
        model = cfg.get("openai_model", "gpt-4o-mini")
        success, res = call_openai_api(openai_key, model, system_prompt, history, clean_msg)
        if success and res.strip():
            reply_text = res.strip()
            used_provider = f"openai ({model})"

    # Fallback to Built-in Contextual Inference Engine
    if not reply_text:
        reply_text = built_in_inference_engine(clean_msg, history, kb, profile)
        used_provider = "cyberpro-neural-crm"

    # 5. Synchronize with Database CRM
    updated_history = list(history)
    updated_history.append({"role": "user", "content": clean_msg})
    updated_history.append({"role": "assistant", "content": reply_text})

    try:
        profile = sync_crm_lead(session_id or f"sess_{int(time.time()*1000)}", profile, updated_history)
    except Exception as e:
        print("CRM sync error:", e)

    return {
        "ok": True,
        "reply": reply_text,
        "provider": used_provider,
        "timestamp": int(time.time()),
        "lead_captured": bool(profile.get("phone") or profile.get("email")),
        "lead_score": profile.get("lead_score", 50),
        "customer_id": profile.get("id")
    }
