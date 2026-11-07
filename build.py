#!/usr/bin/env python3
"""
CYBERPRO - Production Static Site Builder for Cloudflare Pages & GitHub
Generates a complete, verified dist/ directory with zero missing assets and clean URL routing.
"""
import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PUBLIC_DIR = ROOT / "public"
PRIVATE_DIR = ROOT / "private"
DIST_DIR = ROOT / "dist"

def log(msg):
    print(f"[CYBERPRO BUILD] {msg}")

def build():
    log("Starting CYBERPRO Production Build...")
    
    # 1. Clean dist directory
    if DIST_DIR.exists():
        log(f"Cleaning existing {DIST_DIR}...")
        shutil.rmtree(DIST_DIR)
    DIST_DIR.mkdir(parents=True, exist_ok=True)

    # 2. Copy all public files to dist
    log("Copying public assets and pages...")
    for item in PUBLIC_DIR.iterdir():
        dest = DIST_DIR / item.name
        if item.is_dir():
            shutil.copytree(item, dest)
        else:
            shutil.copy2(item, dest)

    # 3. Copy private pages (LMS & CRM) to dist with clean directory fallbacks
    log("Copying LMS and CRM templates to dist...")
    if (PRIVATE_DIR / "lms.html").exists():
        shutil.copy2(PRIVATE_DIR / "lms.html", DIST_DIR / "lms.html")
        (DIST_DIR / "lms").mkdir(exist_ok=True)
        shutil.copy2(PRIVATE_DIR / "lms.html", DIST_DIR / "lms" / "index.html")

    if (PRIVATE_DIR / "admin-crm.html").exists():
        shutil.copy2(PRIVATE_DIR / "admin-crm.html", DIST_DIR / "admin-crm.html")
        (DIST_DIR / "admin").mkdir(exist_ok=True)
        (DIST_DIR / "admin" / "crm").mkdir(parents=True, exist_ok=True)
        shutil.copy2(PRIVATE_DIR / "admin-crm.html", DIST_DIR / "admin" / "crm" / "index.html")
        (DIST_DIR / "admin" / "leads").mkdir(parents=True, exist_ok=True)
        shutil.copy2(PRIVATE_DIR / "admin-crm.html", DIST_DIR / "admin" / "leads" / "index.html")

    # 4. Generate directory-based clean URLs (e.g. /about -> /about/index.html)
    pages = ["about", "ccce", "programs", "contact"]
    for page in pages:
        html_file = DIST_DIR / f"{page}.html"
        if html_file.exists():
            page_dir = DIST_DIR / page
            page_dir.mkdir(exist_ok=True)
            shutil.copy2(html_file, page_dir / "index.html")
            log(f"  + Generated clean route: /{page}/index.html")

    # 5. Write Cloudflare Pages _redirects file
    redirects_content = """# CYBERPRO Cloudflare Pages URL Routing & Clean Fallbacks
/about        /about.html        200
/about/       /about.html        200
/ccce         /ccce.html         200
/ccce/        /ccce.html         200
/programs     /programs.html     200
/programs/    /programs.html     200
/contact      /contact.html      200
/contact/     /contact.html      200
/lms          /lms.html          200
/lms/         /lms.html          200
/admin/crm    /admin-crm.html    200
/admin/crm/   /admin-crm.html    200
/admin/leads  /admin-crm.html    200
/admin/leads/ /admin-crm.html    200
"""
    (DIST_DIR / "_redirects").write_text(redirects_content, encoding="utf-8")
    log("  + Generated Cloudflare Pages _redirects")

    # 6. Write Cloudflare Pages _headers file for caching & security
    headers_content = """/*
  X-Content-Type-Options: nosniff
  X-Frame-Options: SAMEORIGIN
  Referrer-Policy: strict-origin-when-cross-origin

/assets/*
  Cache-Control: public, max-age=31536000, immutable

/*.mp4
  Cache-Control: public, max-age=31536000, immutable
"""
    (DIST_DIR / "_headers").write_text(headers_content, encoding="utf-8")
    log("  + Generated Cloudflare Pages _headers")

    # 7. Verification & Audit
    required_files = [
        "index.html",
        "about.html",
        "ccce.html",
        "programs.html",
        "contact.html",
        "lms.html",
        "admin-crm.html",
        "_redirects",
        "_headers",
        "assets/site-pages.css",
        "assets/cyber-chatbot.js",
        "assets/cyber-chatbot.css",
        "assets/logo-mark.png",
        "assets/cyberpro-guardian-video.mp4",
        "assets/head_frames/f_00.jpg",
        "assets/head_frames/f_29.jpg"
    ]

    missing = []
    for f in required_files:
        if not (DIST_DIR / f).exists():
            missing.append(f)

    if missing:
        log(f"ERROR: Build failed! Missing required files in dist: {missing}")
        sys.exit(1)

    # Count total files and size
    dist_files = list(DIST_DIR.rglob("*"))
    file_count = sum(1 for f in dist_files if f.is_file())
    total_size_mb = sum(f.stat().st_size for f in dist_files if f.is_file()) / (1024 * 1024)

    log("=" * 60)
    log("BUILD SUCCESSFUL!")
    log(f"Output Directory: {DIST_DIR}")
    log(f"Total Files in dist: {file_count}")
    log(f"Total Size: {total_size_mb:.2f} MB")
    log("Ready for deployment to Cloudflare Pages!")
    log("=" * 60)

if __name__ == "__main__":
    build()
