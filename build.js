/**
 * CYBERPRO - Production Static Site Builder for Cloudflare Pages (Node.js runner)
 * Generates a complete, verified dist/ directory with zero missing assets and clean URL routing.
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const PRIVATE_DIR = path.join(ROOT, 'private');
const DIST_DIR = path.join(ROOT, 'dist');

function log(msg) {
  console.log(`[CYBERPRO BUILD] ${msg}`);
}

function copyRecursiveSync(src, dest) {
  const exists = fs.existsSync(src);
  const stats = exists && fs.statSync(src);
  const isDirectory = exists && stats.isDirectory();
  if (isDirectory) {
    if (!fs.existsSync(dest)) {
      fs.mkdirSync(dest, { recursive: true });
    }
    fs.readdirSync(src).forEach((childItemName) => {
      copyRecursiveSync(path.join(src, childItemName), path.join(dest, childItemName));
    });
  } else {
    fs.copyFileSync(src, dest);
  }
}

function build() {
  log('Starting CYBERPRO Production Build (Node.js)...');

  // 1. Clean dist directory
  if (fs.existsSync(DIST_DIR)) {
    log('Cleaning existing dist directory...');
    fs.rmSync(DIST_DIR, { recursive: true, force: true });
  }
  fs.mkdirSync(DIST_DIR, { recursive: true });

  // 2. Copy all public files to dist
  log('Copying public assets and pages...');
  copyRecursiveSync(PUBLIC_DIR, DIST_DIR);

  // 3. Copy private pages (LMS & CRM) to dist with clean directory fallbacks
  log('Copying LMS and CRM templates to dist...');
  const lmsSrc = path.join(PRIVATE_DIR, 'lms.html');
  if (fs.existsSync(lmsSrc)) {
    fs.copyFileSync(lmsSrc, path.join(DIST_DIR, 'lms.html'));
    const lmsDir = path.join(DIST_DIR, 'lms');
    fs.mkdirSync(lmsDir, { recursive: true });
    fs.copyFileSync(lmsSrc, path.join(lmsDir, 'index.html'));
  }

  const crmSrc = path.join(PRIVATE_DIR, 'admin-crm.html');
  if (fs.existsSync(crmSrc)) {
    fs.copyFileSync(crmSrc, path.join(DIST_DIR, 'admin-crm.html'));
    const crmDir = path.join(DIST_DIR, 'admin', 'crm');
    fs.mkdirSync(crmDir, { recursive: true });
    fs.copyFileSync(crmSrc, path.join(crmDir, 'index.html'));

    const leadsDir = path.join(DIST_DIR, 'admin', 'leads');
    fs.mkdirSync(leadsDir, { recursive: true });
    fs.copyFileSync(crmSrc, path.join(leadsDir, 'index.html'));
  }

  // 4. Generate directory-based clean URLs (e.g. /about -> /about/index.html)
  const pages = ['about', 'ccce', 'programs', 'contact'];
  for (const page of pages) {
    const htmlFile = path.join(DIST_DIR, `${page}.html`);
    if (fs.existsSync(htmlFile)) {
      const pageDir = path.join(DIST_DIR, page);
      fs.mkdirSync(pageDir, { recursive: true });
      fs.copyFileSync(htmlFile, path.join(pageDir, 'index.html'));
      log(`  + Generated clean route: /${page}/index.html`);
    }
  }

  // 5. Write Cloudflare Pages _redirects file
  const redirectsContent = `# CYBERPRO Cloudflare Pages URL Routing & Clean Fallbacks
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
`;
  fs.writeFileSync(path.join(DIST_DIR, '_redirects'), redirectsContent, 'utf-8');
  log('  + Generated Cloudflare Pages _redirects');

  // 6. Write Cloudflare Pages _headers file
  const headersContent = `/*
  X-Content-Type-Options: nosniff
  X-Frame-Options: SAMEORIGIN
  Referrer-Policy: strict-origin-when-cross-origin

/assets/*
  Cache-Control: public, max-age=31536000, immutable

/*.mp4
  Cache-Control: public, max-age=31536000, immutable
`;
  fs.writeFileSync(path.join(DIST_DIR, '_headers'), headersContent, 'utf-8');
  log('  + Generated Cloudflare Pages _headers');

  // 7. Verify required files
  const requiredFiles = [
    'index.html',
    'about.html',
    'ccce.html',
    'programs.html',
    'contact.html',
    'lms.html',
    'admin-crm.html',
    '_redirects',
    '_headers',
    path.join('assets', 'site-pages.css'),
    path.join('assets', 'cyber-chatbot.js'),
    path.join('assets', 'cyber-chatbot.css'),
    path.join('assets', 'logo-mark.png'),
    path.join('assets', 'cyberpro-guardian-video.mp4'),
    path.join('assets', 'head_frames', 'f_00.jpg'),
    path.join('assets', 'head_frames', 'f_29.jpg'),
  ];

  const missing = [];
  for (const f of requiredFiles) {
    if (!fs.existsSync(path.join(DIST_DIR, f))) {
      missing.push(f);
    }
  }

  if (missing.length > 0) {
    log(`ERROR: Build failed! Missing files in dist: ${missing.join(', ')}`);
    process.exit(1);
  }

  log('============================================================');
  log('BUILD SUCCESSFUL!');
  log(`Output Directory: ${DIST_DIR}`);
  log('Ready for Cloudflare Pages deployment!');
  log('============================================================');
}

build();
