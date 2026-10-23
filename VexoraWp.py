#!/usr/bin/env python3

import os
import sys
import re
import json
import argparse
import time
import concurrent.futures
from urllib.parse import urljoin, urlparse, urlencode
from datetime import datetime
from collections import defaultdict

# ══════════════════════════════════════════════════════════════════
#  WINDOWS CONSOLE & UTF-8 COMPATIBILITY
# ══════════════════════════════════════════════════════════════════
if sys.platform.startswith("win"):
    os.system("")  # Initialize VT100 ANSI escape support
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import requests
from requests.adapters import HTTPAdapter

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("[!] Missing dependency: pip install requests beautifulsoup4")
    sys.exit(1)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ══════════════════════════════════════════════════════════════════
#  COLORS & DISPLAY
# ══════════════════════════════════════════════════════════════════
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BLUE   = "\033[94m"
    MAGENTA= "\033[95m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

def banner():
    print(f"""{C.CYAN}{C.BOLD}
  ██╗   ██╗███████╗██╗  ██╗ ██████╗ ██████╗  █████╗ ██╗    ██╗██████╗ 
  ██║   ██║██╔════╝╚██╗██╔╝██╔═══██╗██╔══██╗██╔══██╗██║    ██║██╔══██╗
  ██║   ██║█████╗   ╚███╔╝ ██║   ██║██████╔╝███████║██║ █╗ ██║██████╔╝
  ╚██╗ ██╔╝██╔══╝   ██╔██╗ ██║   ██║██╔══██╗██╔══██║██║███╗██║██╔═══╝ 
   ╚████╔╝ ███████╗██╔╝ ██╗╚██████╔╝██║  ██║██║  ██║╚███╔███╔╝██║     
    ╚═══╝  ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝     
       {C.RESET}{C.DIM}Passive WordPress Reconnaissance & Security Audit Suite{C.RESET}
""")

def section(title, icon="◈"):
    width = 62
    print(f"\n{C.CYAN}{C.BOLD}{'─'*width}")
    print(f"  {icon}  {title}")
    print(f"{'─'*width}{C.RESET}")

def info(msg):   print(f"  {C.BLUE}[i]{C.RESET} {msg}")
def good(msg):   print(f"  {C.GREEN}[+]{C.RESET} {msg}")
def warn(msg):   print(f"  {C.YELLOW}[!]{C.RESET} {msg}")
def bad(msg):    print(f"  {C.RED}[✗]{C.RESET} {msg}")
def dim(msg):    print(f"  {C.DIM}{msg}{C.RESET}")


# ══════════════════════════════════════════════════════════════════
#  HTTP SESSION & NETWORKING
# ══════════════════════════════════════════════════════════════════
def make_session(user_agent=None, proxy=None, timeout=12, pool_size=50):
    s = requests.Session()
    # Configure connection pool to avoid thread pool exhaustion warnings
    adapter = HTTPAdapter(pool_connections=pool_size, pool_maxsize=pool_size, max_retries=1)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update({
        "User-Agent": user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    })
    s.verify = False
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    s._timeout = timeout
    return s

def get(session, url, allow_redirects=True, stream=False):
    try:
        return session.get(url, timeout=session._timeout,
                           allow_redirects=allow_redirects, stream=stream)
    except Exception:
        return None

def normalize(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


# ══════════════════════════════════════════════════════════════════
#  WORDPRESS DETECTION
# ══════════════════════════════════════════════════════════════════
def detect_wordpress(session, base):
    signals = []
    checks = {
        "wp-login.php":    f"{base}/wp-login.php",
        "wp-admin/":       f"{base}/wp-admin/",
        "xmlrpc.php":      f"{base}/xmlrpc.php",
        "wp-includes/":    f"{base}/wp-includes/",
        "wp-cron.php":     f"{base}/wp-cron.php",
    }
    for label, url in checks.items():
        r = get(session, url, allow_redirects=False)
        if r and r.status_code in (200, 301, 302, 403, 405):
            signals.append(label)

    r = get(session, base)
    if r:
        if "wp-content" in r.text:   signals.append("wp-content in source")
        if "wp-includes" in r.text:  signals.append("wp-includes in source")
        if "WordPress" in r.text:    signals.append("WordPress string in source")

    return signals


# ══════════════════════════════════════════════════════════════════
#  SERVER & TECHNOLOGY FINGERPRINT
# ══════════════════════════════════════════════════════════════════
def fingerprint_server(session, base):
    info_map = {}
    r = get(session, base)
    if not r:
        return info_map

    h = {k.lower(): v for k, v in r.headers.items()}
    info_map["server"]          = h.get("server", "")
    info_map["x_powered_by"]    = h.get("x-powered-by", "")
    info_map["content_type"]    = h.get("content-type", "")
    info_map["cache_control"]   = h.get("cache-control", "")
    info_map["x_cache"]         = h.get("x-cache", "")
    info_map["cf_ray"]          = h.get("cf-ray", "")          # Cloudflare
    info_map["via"]             = h.get("via", "")
    info_map["x_varnish"]       = h.get("x-varnish", "")       # Varnish cache
    info_map["x_litespeed_tag"] = h.get("x-litespeed-tag", "") # LiteSpeed
    info_map["x_generator"]     = h.get("x-generator", "")
    info_map["protocol"]        = r.url.split(":")[0].upper()
    info_map["final_url"]       = r.url
    info_map["status_code"]     = r.status_code
    info_map["response_time_ms"]= int(r.elapsed.total_seconds() * 1000)
    info_map["encoding"]        = r.encoding or ""
    info_map["cookies"]         = {c.name: c.value for c in session.cookies}

    # CDN / WAF detection
    waf_signatures = {
        "Cloudflare":   ["cf-ray", "cloudflare"],
        "Sucuri":       ["x-sucuri-id", "sucuri"],
        "Wordfence":    ["wordfence"],
        "AWS CloudFront": ["x-amz-cf-id", "cloudfront"],
        "Akamai":       ["x-akamai", "akamai"],
        "Imperva":      ["x-iinfo", "incapsula"],
        "ModSecurity":  ["mod_security", "modsec"],
    }
    detected_waf = []
    full_text = str(r.headers).lower() + r.text[:2000].lower()
    for waf, sigs in waf_signatures.items():
        if any(sig in full_text for sig in sigs):
            detected_waf.append(waf)
    info_map["waf_cdn"] = detected_waf

    # PHP version from header
    php_match = re.search(r'PHP/([\d.]+)', h.get("x-powered-by", ""), re.I)
    if php_match:
        info_map["php_version"] = php_match.group(1)

    # SSL info
    if base.startswith("https://"):
        try:
            import ssl, socket
            host = urlparse(base).netloc.split(":")[0]
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as s2:
                s2.settimeout(5)
                s2.connect((host, 443))
                cert = s2.getpeercert()
                info_map["ssl_issuer"]  = dict(x[0] for x in cert.get("issuer", []))
                info_map["ssl_subject"] = dict(x[0] for x in cert.get("subject", []))
                info_map["ssl_expires"] = cert.get("notAfter", "")
                info_map["ssl_version"] = s2.version()
        except Exception:
            pass

    # Technology from source
    tech = []
    src = r.text[:20000]
    tech_patterns = {
        "jQuery":            r'jquery[.-]([\d.]+)',
        "jQuery UI":         r'jquery-ui[.-]([\d.]+)',
        "Bootstrap":         r'bootstrap[.-]([\d.]+)',
        "Google Analytics":  r'google-analytics\.com|gtag\(',
        "Google Tag Manager":r'googletagmanager\.com',
        "Facebook Pixel":    r'connect\.facebook\.net',
        "WooCommerce":       r'woocommerce',
        "Elementor":         r'elementor',
        "Divi":              r'/et-core/',
        "Beaver Builder":    r'fl-builder',
        "WPBakery":          r'wpb_js_composer|vc_row',
        "WPML":              r'sitepress|wpml',
        "Polylang":          r'polylang',
    }
    for name, pattern in tech_patterns.items():
        if re.search(pattern, src, re.I):
            tech.append(name)
    info_map["technologies"] = tech

    return info_map


# ══════════════════════════════════════════════════════════════════
#  WORDPRESS VERSION
# ══════════════════════════════════════════════════════════════════
def detect_wp_version(session, base):
    sources = {}

    probes = [
        (f"{base}/readme.html",             r'[Vv]ersion\s+([\d.]+)'),
        (f"{base}/feed/",                   r'\?v=([\d.]+)'),
        (f"{base}/?feed=rss2",              r'\?v=([\d.]+)'),
        (f"{base}/wp-links-opml.php",       r'generator="WordPress/([\d.]+)'),
        (f"{base}/wp-admin/install.php",    r'WordPress\s+([\d.]+)'),
    ]
    for url, pattern in probes:
        r = get(session, url)
        if r and r.status_code == 200:
            m = re.search(pattern, r.text)
            if m:
                key = url.split(base)[-1] or url
                sources[key] = m.group(1)

    # Meta generator
    r = get(session, base)
    if r:
        m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s*([\d.]+)', r.text, re.I)
        if m:
            sources["meta generator"] = m.group(1)
        m = re.search(r'ver=([\d.]+)["\'].*?wp-includes', r.text)
        if m:
            sources["script ver param"] = m.group(1)

    return sources


# ══════════════════════════════════════════════════════════════════
#  USER / ADMIN ENUMERATION
# ══════════════════════════════════════════════════════════════════
def enumerate_users(session, base):
    users = {}

    # ── REST API ──────────────────────────────────────────────────
    for endpoint in [
        f"{base}/wp-json/wp/v2/users",
        f"{base}/wp-json/wp/v2/users?per_page=100",
        f"{base}/?rest_route=/wp/v2/users",
    ]:
        r = get(session, endpoint)
        if r and r.status_code == 200:
            try:
                for u in r.json():
                    uid = u.get("id", 0)
                    users[uid] = {
                        "id":          uid,
                        "login":       u.get("slug", ""),
                        "name":        u.get("name", ""),
                        "url":         u.get("link", ""),
                        "avatar":      list(u.get("avatar_urls", {}).values())[-1] if u.get("avatar_urls") else "",
                        "description": u.get("description", ""),
                        "source":      "REST API /wp/v2/users",
                    }
            except Exception:
                pass

    # ── ?author= redirect ─────────────────────────────────────────
    for i in range(1, 21):
        r = get(session, f"{base}/?author={i}", allow_redirects=True)
        if r and r.status_code == 200 and "/author/" in r.url:
            slug = r.url.split("/author/")[-1].strip("/").split("?")[0]
            if slug and i not in users:
                soup = BeautifulSoup(r.text, "html.parser")
                title_tag = soup.find("title")
                name = title_tag.get_text(strip=True).split("|")[0].strip() if title_tag else slug
                users[i] = {
                    "id": i, "login": slug, "name": name,
                    "url": r.url, "avatar": "", "description": "",
                    "source": "?author= redirect",
                }

    # ── Sitemaps ──────────────────────────────────────────────────
    for sitemap_url in [f"{base}/sitemap_author.xml", f"{base}/author-sitemap.xml"]:
        r = get(session, sitemap_url)
        if r and r.status_code == 200:
            for m in re.finditer(r'<loc>([^<]*/author/([^/<]+)/[^<]*)</loc>', r.text):
                slug = m.group(2)
                if not any(u.get("login") == slug for u in users.values()):
                    uid = f"sitemap_{slug}"
                    users[uid] = {
                        "id": "?", "login": slug, "name": slug,
                        "url": m.group(1), "avatar": "", "description": "",
                        "source": "sitemap",
                    }

    # ── oEmbed endpoint ───────────────────────────────────────────
    r = get(session, f"{base}/wp-json/oembed/1.0/embed?url={base}&format=json")
    if r and r.status_code == 200:
        try:
            data = r.json()
            author_name = data.get("author_name", "")
            author_url  = data.get("author_url", "")
            if author_name and not any(u.get("name") == author_name for u in users.values()):
                uid = f"oembed_{author_name}"
                users[uid] = {
                    "id": "?", "login": author_name, "name": author_name,
                    "url": author_url, "avatar": "", "description": "",
                    "source": "oEmbed",
                }
        except Exception:
            pass

    return list(users.values())


# ══════════════════════════════════════════════════════════════════
#  EMAIL HARVESTING
# ══════════════════════════════════════════════════════════════════
EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
SKIP_DOMAINS = {"example.com", "domain.com", "sentry.io", "example.org",
                "wordpress.org", "schema.org", "w3.org", "yoursite.com"}

def harvest_emails(session, base, max_pages=10):
    emails = {}
    crawl_queue = [base, f"{base}/contact", f"{base}/about", f"{base}/about-us",
                   f"{base}/contact-us", f"{base}/team", f"{base}/our-team",
                   f"{base}/staff", f"{base}/sitemap.xml"]

    # Also grab links from homepage
    r = get(session, base)
    if r:
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.startswith("/") or base in href:
                crawl_queue.append(urljoin(base, href))

    seen_urls = set()
    for url in crawl_queue[:max_pages]:
        if url in seen_urls:
            continue
        seen_urls.add(url)
        r = get(session, url)
        if not r or r.status_code != 200:
            continue
        # Also check mailto: links
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.find_all("a", href=True):
            if a["href"].startswith("mailto:"):
                em = a["href"].replace("mailto:", "").split("?")[0].strip()
                if em and "@" in em:
                    domain = em.split("@")[-1].lower()
                    if domain not in SKIP_DOMAINS:
                        emails[em] = {"email": em, "source": url, "context": "mailto link"}
        # Regex scan
        for m in EMAIL_RE.finditer(r.text):
            em = m.group(0).lower()
            domain = em.split("@")[-1]
            if domain not in SKIP_DOMAINS and em not in emails:
                emails[em] = {"email": em, "source": url, "context": "page text"}

    return list(emails.values())


# ══════════════════════════════════════════════════════════════════
#  PLUGIN DETECTION
# ══════════════════════════════════════════════════════════════════
COMMON_PLUGINS = [
    "akismet","contact-form-7","woocommerce","jetpack","wordpress-seo","yoast-seo",
    "wordfence","wpforms-lite","elementor","classic-editor","updraftplus",
    "really-simple-ssl","litespeed-cache","all-in-one-wp-security-and-firewall",
    "wps-hide-login","wp-super-cache","wp-smushit","mailchimp-for-wp",
    "redirection","tablepress","wp-optimize","wp-file-manager",
    "advanced-custom-fields","shortcodes-ultimate","easy-digital-downloads",
    "buddypress","bbpress","wp-rocket","wp-mail-smtp","ninja-forms",
    "the-events-calendar","all-in-one-seo-pack","duplicate-page",
    "broken-link-checker","limit-login-attempts-reloaded","loginizer",
    "monsterinsights","rank-math","smush","sucuri-scanner","ithemes-security",
    "polylang","wpml","user-role-editor","members","ultimate-member",
    "enable-media-replace","regenerate-thumbnails","query-monitor",
    "health-check","debug-bar","wp-fastest-cache","w3-total-cache",
    "beaver-builder","divi","fusion-builder","wpbakery",
    "gravity-forms","formidable","forminator","fluent-forms",
    "mailpoet","newsletter","wp-ses","sendgrid","mailgun-for-wp",
    "woocommerce-subscriptions","woocommerce-payments","stripe-payments",
    "easy-paypal-donation","give","charitable","learnpress","learndash",
    "tutor","lifter-lms","memberpress","paid-memberships-pro",
    "wp-job-manager","wp-postratings","disqus-comment-system",
    "cookie-notice","cookie-law-info","gdpr-cookie-compliance",
    "wp-gdpr-compliance","complianz","cookiebot",
    "social-warfare","sassy-social-share","addtoany",
    "nextgen-gallery","envira-gallery","modula",
    "wp-table-of-contents","easy-table-of-contents",
    "schema-and-structured-data-for-wp","schema-markup-rich-snippets",
    "wp-seopress","squirrly-seo","the-seo-framework",
    "imagify","ewww-image-optimizer","shortpixel-image-optimiser",
    "autoptimize","fast-velocity-minify","sg-cachepress",
    "cloudflare","aruba-hispeed-cache","breeze",
    "translatepress-multilingual","gtranslate","google-language-translator",
    "wpcf7-recaptcha","recaptcha","advanced-google-recaptcha",
    "wp-statistics","statcounter","slimstat-analytics",
]

def probe_plugin(session, base, slug):
    for path in [
        f"{base}/wp-content/plugins/{slug}/readme.txt",
        f"{base}/wp-content/plugins/{slug}/README.txt",
        f"{base}/wp-content/plugins/{slug}/{slug}.php",
    ]:
        r = get(session, path)
        if r and r.status_code == 200 and len(r.text) > 20:
            text = r.text
            version   = None
            name      = slug
            desc      = ""
            requires  = ""
            tested_up = ""

            m = re.search(r'Stable tag:\s*([\d.]+)', text, re.I)
            if m: version = m.group(1)
            m = re.search(r'Version:\s*([\d.]+)', text, re.I)
            if m and not version: version = m.group(1)
            m = re.search(r'(?:Plugin Name|Name):\s*(.+)', text, re.I)
            if m: name = m.group(1).strip()
            m = re.search(r'(?:Description|Short Description):\s*(.+)', text, re.I)
            if m: desc = m.group(1).strip()[:120]
            m = re.search(r'Requires at least:\s*([\d.]+)', text, re.I)
            if m: requires = m.group(1)
            m = re.search(r'Tested up to:\s*([\d.]+)', text, re.I)
            if m: tested_up = m.group(1)

            return {
                "slug":        slug,
                "name":        name,
                "version":     version,
                "description": desc,
                "requires_wp": requires,
                "tested_up_to":tested_up,
                "accessible_file": path,
                "source":      "direct probe",
            }
    return None

def extract_plugins_from_source(session, base):
    found = {}
    pages = [base, f"{base}/", f"{base}/sitemap.xml"]
    for url in pages:
        r = get(session, url)
        if not r: continue
        for m in re.finditer(r'wp-content/plugins/([a-z0-9_-]+)/', r.text):
            slug = m.group(1)
            if slug not in found:
                found[slug] = {
                    "slug": slug, "name": slug, "version": None,
                    "source": "page source", "description": "",
                    "requires_wp": "", "tested_up_to": "", "accessible_file": "",
                }
    return found

def enumerate_plugins(session, base, threads=25):
    found = extract_plugins_from_source(session, base)
    info(f"Found {len(found)} plugins from page source")

    # REST API (if auth available)
    r = get(session, f"{base}/wp-json/wp/v2/plugins")
    if r and r.status_code == 200:
        try:
            for p in r.json():
                s = p.get("plugin", "").split("/")[0]
                if s:
                    found[s] = {
                        "slug": s, "name": p.get("name", s),
                        "version": p.get("version"), "description": "",
                        "source": "REST API", "requires_wp": "",
                        "tested_up_to": "", "accessible_file": "",
                    }
        except Exception:
            pass

    all_slugs = list(set(list(found.keys()) + COMMON_PLUGINS))

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(probe_plugin, session, base, sl): sl
                for sl in all_slugs if sl not in found}
        for fut in concurrent.futures.as_completed(futs):
            result = fut.result()
            if result:
                found[result["slug"]] = result

    return sorted(found.values(), key=lambda x: x["slug"])


# ══════════════════════════════════════════════════════════════════
#  THEME DETECTION
# ══════════════════════════════════════════════════════════════════
def enumerate_themes(session, base):
    themes = {}
    r = get(session, base)
    if r:
        for m in re.finditer(r'wp-content/themes/([a-z0-9_-]+)/', r.text):
            slug = m.group(1)
            themes[slug] = {"slug": slug}

    for slug in list(themes.keys()):
        r2 = get(session, f"{base}/wp-content/themes/{slug}/style.css")
        if r2 and r2.status_code == 200:
            txt = r2.text
            def grab(pat): m = re.search(pat, txt, re.I); return m.group(1).strip() if m else ""
            themes[slug].update({
                "name":        grab(r'Theme Name:\s*(.+)'),
                "version":     grab(r'Version:\s*([\d.]+)'),
                "author":      grab(r'Author:\s*(.+)'),
                "author_uri":  grab(r'Author URI:\s*(.+)'),
                "theme_uri":   grab(r'Theme URI:\s*(.+)'),
                "description": grab(r'Description:\s*(.+)')[:120],
                "template":    grab(r'Template:\s*(.+)'),  # parent theme
                "text_domain": grab(r'Text Domain:\s*(.+)'),
            })

    return list(themes.values())


# ══════════════════════════════════════════════════════════════════
#  SITE STRUCTURE MAPPING
# ══════════════════════════════════════════════════════════════════
def map_site_structure(session, base):
    structure = {
        "pages":       [],
        "categories":  [],
        "tags":        [],
        "posts":       [],
        "custom_post_types": [],
        "menus":       [],
        "media":       [],
    }

    # REST API pages
    r = get(session, f"{base}/wp-json/wp/v2/pages?per_page=50")
    if r and r.status_code == 200:
        try:
            for p in r.json():
                structure["pages"].append({
                    "id":     p.get("id"),
                    "title":  p.get("title", {}).get("rendered", ""),
                    "slug":   p.get("slug", ""),
                    "url":    p.get("link", ""),
                    "status": p.get("status", ""),
                    "template": p.get("template", ""),
                })
        except Exception:
            pass

    # REST API posts
    r = get(session, f"{base}/wp-json/wp/v2/posts?per_page=20")
    if r and r.status_code == 200:
        try:
            for p in r.json():
                structure["posts"].append({
                    "id":       p.get("id"),
                    "title":    p.get("title", {}).get("rendered", ""),
                    "slug":     p.get("slug", ""),
                    "url":      p.get("link", ""),
                    "date":     p.get("date", ""),
                    "author":   p.get("author"),
                    "categories": p.get("categories", []),
                })
        except Exception:
            pass

    # Categories
    r = get(session, f"{base}/wp-json/wp/v2/categories?per_page=50")
    if r and r.status_code == 200:
        try:
            for c in r.json():
                structure["categories"].append({
                    "id":    c.get("id"),
                    "name":  c.get("name", ""),
                    "slug":  c.get("slug", ""),
                    "count": c.get("count", 0),
                    "url":   c.get("link", ""),
                })
        except Exception:
            pass

    # Tags
    r = get(session, f"{base}/wp-json/wp/v2/tags?per_page=50")
    if r and r.status_code == 200:
        try:
            for t in r.json():
                structure["tags"].append({
                    "id":    t.get("id"),
                    "name":  t.get("name", ""),
                    "slug":  t.get("slug", ""),
                    "count": t.get("count", 0),
                })
        except Exception:
            pass

    # Custom post types
    r = get(session, f"{base}/wp-json/wp/v2/types")
    if r and r.status_code == 200:
        try:
            data = r.json()
            for cpt_slug, cpt_data in data.items():
                if cpt_slug not in ("post", "page", "attachment", "revision",
                                    "nav_menu_item", "custom_css", "customize_changeset",
                                    "oembed_cache", "user_request", "wp_block", "wp_template"):
                    structure["custom_post_types"].append({
                        "slug":        cpt_slug,
                        "name":        cpt_data.get("name", cpt_slug),
                        "rest_base":   cpt_data.get("rest_base", ""),
                        "description": cpt_data.get("description", ""),
                    })
        except Exception:
            pass

    # Menus
    r = get(session, f"{base}/wp-json/wp/v2/menus")
    if r and r.status_code == 200:
        try:
            for m in r.json():
                structure["menus"].append({
                    "id":   m.get("id"),
                    "name": m.get("name", ""),
                    "slug": m.get("slug", ""),
                    "count": m.get("count", 0),
                })
        except Exception:
            pass

    # Sitemap parsing
    r = get(session, f"{base}/sitemap.xml")
    if not r or r.status_code != 200:
        r = get(session, f"{base}/sitemap_index.xml")
    if r and r.status_code == 200:
        urls = re.findall(r'<loc>([^<]+)</loc>', r.text)
        structure["sitemap_urls"] = urls[:100]

    # Robots.txt
    r = get(session, f"{base}/robots.txt")
    if r and r.status_code == 200:
        structure["robots_txt"] = r.text.strip()

    return structure


# ══════════════════════════════════════════════════════════════════
#  SECURITY EXPOSURE CHECKS (passive only)
# ══════════════════════════════════════════════════════════════════
SENSITIVE_PATHS = [
    # WordPress core
    ("/wp-login.php",                    "Admin login page"),
    ("/wp-admin/",                       "Admin dashboard"),
    ("/xmlrpc.php",                      "XML-RPC endpoint"),
    ("/wp-cron.php",                     "WP-Cron"),
    ("/wp-config.php",                   "Config file"),
    ("/wp-config.php.bak",               "Config backup"),
    ("/wp-config.bak",                   "Config backup"),
    ("/wp-config.old",                   "Config backup"),
    ("/wp-config~",                      "Config backup (tilde)"),
    ("/readme.html",                     "Readme (version leak)"),
    ("/license.txt",                     "License file"),
    ("/wp-content/debug.log",            "Debug log"),
    ("/wp-content/uploads/",             "Uploads directory"),
    ("/wp-content/plugins/",             "Plugins directory"),
    ("/wp-content/themes/",              "Themes directory"),
    ("/wp-includes/",                    "WP Includes"),
    # System files
    ("/.env",                            ".env file"),
    ("/.htaccess",                       ".htaccess"),
    ("/.htpasswd",                       ".htpasswd"),
    ("/.git/HEAD",                       "Git HEAD"),
    ("/.git/config",                     "Git config"),
    ("/phpinfo.php",                     "phpinfo()"),
    ("/info.php",                        "phpinfo()"),
    ("/php.php",                         "phpinfo()"),
    ("/test.php",                        "Test PHP file"),
    ("/server-status",                   "Apache server-status"),
    ("/server-info",                     "Apache server-info"),
    # Backups
    ("/backup.zip",                      "Backup archive"),
    ("/backup.tar.gz",                   "Backup archive"),
    ("/site.zip",                        "Site backup"),
    ("/www.zip",                         "Site backup"),
    ("/wordpress.zip",                   "WordPress backup"),
    ("/db.sql",                          "Database dump"),
    ("/database.sql",                    "Database dump"),
    ("/wp-content/uploads/db.sql",       "DB dump in uploads"),
    # Other
    ("/wp-json/",                        "REST API root"),
    ("/wp-json/wp/v2/users",             "REST users endpoint"),
    ("/wp-trackback.php",                "Trackbacks"),
    ("/wp-comments-post.php",            "Comments endpoint"),
    ("/sitemap.xml",                     "Sitemap"),
    ("/sitemap_index.xml",               "Sitemap index"),
    ("/robots.txt",                      "Robots.txt"),
]

def check_exposures(session, base):
    results = []
    
    # Establish a soft-404 baseline using a randomized non-existent probe
    soft_404_len = None
    probe_url = f"{base}/vexora_404_probe_{int(time.time())}.html"
    r_probe = get(session, probe_url, allow_redirects=False)
    if r_probe and r_probe.status_code == 200:
        soft_404_len = len(r_probe.content)

    for path, label in SENSITIVE_PATHS:
        url = base + path
        r = get(session, url, allow_redirects=False)
        if not r:
            continue
            
        content_len = len(r.content)
        content_type = r.headers.get("content-type", "").lower()
        
        # Filter out soft-404 false positives on servers returning 200 for missing pages
        if r.status_code == 200:
            if soft_404_len is not None and abs(content_len - soft_404_len) <= 64:
                continue
                
            # Database backups, env, and archives should never return HTML
            ext = path.split("?")[0].lower()
            if any(ext.endswith(e) for e in [".zip", ".tar.gz", ".sql", ".bak", ".env", ".log"]):
                if "text/html" in content_type or "<html" in r.text[:300].lower():
                    continue

        entry = {
            "path":   path,
            "label":  label,
            "url":    url,
            "status": r.status_code,
            "size":   content_len,
        }
        if r.status_code in (200, 403):
            results.append(entry)

    return results

def check_security_headers(session, base):
    r = get(session, base)
    if not r:
        return {}
    h = {k.lower(): v for k, v in r.headers.items()}
    header_checks = {
        "Strict-Transport-Security": "strict-transport-security",
        "Content-Security-Policy":   "content-security-policy",
        "X-Frame-Options":           "x-frame-options",
        "X-Content-Type-Options":    "x-content-type-options",
        "Referrer-Policy":           "referrer-policy",
        "Permissions-Policy":        "permissions-policy",
        "X-XSS-Protection":          "x-xss-protection",
        "Cross-Origin-Opener-Policy":"cross-origin-opener-policy",
        "Cross-Origin-Resource-Policy":"cross-origin-resource-policy",
    }
    return {name: h.get(key, "MISSING") for name, key in header_checks.items()}


# ══════════════════════════════════════════════════════════════════
#  REST API RECONNAISSANCE
# ══════════════════════════════════════════════════════════════════
def probe_rest_api(session, base):
    info_map = {}
    r = get(session, f"{base}/wp-json/")
    if r and r.status_code == 200:
        try:
            data = r.json()
            info_map["name"]        = data.get("name", "")
            info_map["description"] = data.get("description", "")
            info_map["url"]         = data.get("url", "")
            info_map["home"]        = data.get("home", "")
            info_map["gmt_offset"]  = data.get("gmt_offset")
            info_map["timezone"]    = data.get("timezone_string", "")
            info_map["namespaces"]  = data.get("namespaces", [])
            info_map["wp_version"]  = data.get("wp_version") or data.get("version", "")
            # Exposed routes (top-level keys)
            routes = list(data.get("routes", {}).keys())
            info_map["route_count"] = len(routes)
            info_map["routes_sample"] = routes[:30]
        except Exception:
            pass
    return info_map


# ══════════════════════════════════════════════════════════════════
#  SOCIAL MEDIA & CONTACT INFO
# ══════════════════════════════════════════════════════════════════
SOCIAL_PATTERNS = {
    "Facebook":   r'facebook\.com/(?!sharer|share|plugins|dialog|permalink)([a-zA-Z0-9.\-_/]+)',
    "Twitter/X":  r'(?:twitter|x)\.com/([a-zA-Z0-9_]+)',
    "Instagram":  r'instagram\.com/([a-zA-Z0-9_.]+)',
    "LinkedIn":   r'linkedin\.com/(?:company|in)/([a-zA-Z0-9._-]+)',
    "YouTube":    r'youtube\.com/(?:channel|c|user)/([a-zA-Z0-9_-]+)',
    "TikTok":     r'tiktok\.com/@([a-zA-Z0-9_.]+)',
    "Pinterest":  r'pinterest\.com/([a-zA-Z0-9_/]+)',
    "GitHub":     r'github\.com/([a-zA-Z0-9_-]+)',
    "Telegram":   r't\.me/([a-zA-Z0-9_]+)',
    "WhatsApp":   r'wa\.me/([0-9+]+)',
}
PHONE_RE = re.compile(r'(?:tel:|phone:)?\+?[\d\s\-().]{10,20}(?=\s|<|"|\')', re.I)

def extract_social_and_contact(session, base):
    social  = defaultdict(set)
    phones  = set()

    pages = [base, f"{base}/contact", f"{base}/about", f"{base}/about-us",
             f"{base}/contact-us", f"{base}/", f"{base}/?page_id=2"]

    for url in pages:
        r = get(session, url)
        if not r or r.status_code != 200:
            continue
        for platform, pat in SOCIAL_PATTERNS.items():
            for m in re.finditer(pat, r.text, re.I):
                handle = m.group(1).strip("/").split("?")[0]
                if 3 < len(handle) < 60:
                    social[platform].add(handle)

        # Phone numbers via tel: links
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.find_all("a", href=True):
            if a["href"].startswith("tel:"):
                phones.add(a["href"].replace("tel:", "").strip())

    return {
        "social_media": {k: list(v) for k, v in social.items()},
        "phones":       list(phones),
    }


# ══════════════════════════════════════════════════════════════════
#  KNOWN VULNERABILITY LOOKUP  (offline CVE map — no auth needed)
# ══════════════════════════════════════════════════════════════════
# A curated sample of high-profile WordPress plugin CVEs
PLUGIN_VULN_DB = {
    "elementor":             [{"cve": "CVE-2023-48777", "severity": "CRITICAL", "desc": "Arbitrary file upload via unprotected REST route", "fixed_in": "3.18.2"}],
    "wpforms-lite":          [{"cve": "CVE-2024-2783",  "severity": "HIGH",     "desc": "Missing capability check on form deletion", "fixed_in": "1.8.8"}],
    "contact-form-7":        [{"cve": "CVE-2023-6449",  "severity": "HIGH",     "desc": "Unrestricted file upload", "fixed_in": "5.8.4"}],
    "wp-file-manager":       [{"cve": "CVE-2020-25213", "severity": "CRITICAL", "desc": "Unauthenticated RCE via elFinder", "fixed_in": "6.9"}],
    "wordfence":             [{"cve": "CVE-2023-2007",  "severity": "MEDIUM",   "desc": "IP bypass via header spoofing", "fixed_in": "7.10.3"}],
    "jetpack":               [{"cve": "CVE-2023-2996",  "severity": "HIGH",     "desc": "Shortcode injection leading to XSS", "fixed_in": "12.1.1"}],
    "woocommerce":           [{"cve": "CVE-2021-32789", "severity": "HIGH",     "desc": "SQL injection via order search", "fixed_in": "5.5.1"}],
    "updraftplus":           [{"cve": "CVE-2023-32960", "severity": "HIGH",     "desc": "Insecure direct object reference", "fixed_in": "1.23.9"}],
    "advanced-custom-fields":[{"cve": "CVE-2023-30777", "severity": "HIGH",     "desc": "Reflected XSS in admin field builder", "fixed_in": "6.1.6"}],
    "slider-revolution":     [{"cve": "CVE-2014-9734",  "severity": "CRITICAL", "desc": "Arbitrary file download (old versions)", "fixed_in": "4.2"}],
    "wpml":                  [{"cve": "CVE-2024-6386",  "severity": "CRITICAL", "desc": "RCE via Server-Side Template Injection in WPML shortcode", "fixed_in": "4.6.13"}],
    "litespeed-cache":       [{"cve": "CVE-2024-44000", "severity": "CRITICAL", "desc": "Unauthenticated privilege escalation via cookie stealing", "fixed_in": "6.5.1"}],
    "really-simple-ssl":     [{"cve": "CVE-2024-10924", "severity": "CRITICAL", "desc": "Authentication bypass in 2FA implementation", "fixed_in": "9.1.2"}],
    "loginizer":             [{"cve": "CVE-2020-27615", "severity": "CRITICAL", "desc": "SQL injection in username field", "fixed_in": "1.6.4"}],
    "all-in-one-seo-pack":   [{"cve": "CVE-2021-25036", "severity": "HIGH",     "desc": "Privilege escalation via broken access control", "fixed_in": "4.1.5.2"}],
    "yoast-seo":             [{"cve": "CVE-2021-25116", "severity": "MEDIUM",   "desc": "Reflected XSS via get parameter", "fixed_in": "17.3"}],
    "ninja-forms":           [{"cve": "CVE-2022-34819", "severity": "CRITICAL", "desc": "Code injection — arbitrary code execution", "fixed_in": "3.6.11"}],
}

def parse_version(ver_str):
    if not ver_str or ver_str == "?":
        return None
    try:
        from packaging.version import parse
        clean = re.sub(r'^[^\d]*', '', str(ver_str))
        return parse(clean)
    except Exception:
        nums = [int(n) for n in re.findall(r'\d+', str(ver_str))]
        return tuple(nums) if nums else None

def lookup_vulnerabilities(plugins):
    vulns = []
    for p in plugins:
        slug = p.get("slug", "")
        installed_ver = p.get("version")
        if slug in PLUGIN_VULN_DB:
            for v in PLUGIN_VULN_DB[slug]:
                fixed_in = v.get("fixed_in", "")
                
                status = "UNVERIFIED"
                p_inst = parse_version(installed_ver)
                p_fixed = parse_version(fixed_in)
                
                if p_inst and p_fixed:
                    try:
                        if p_inst < p_fixed:
                            status = "VULNERABLE"
                        else:
                            status = "PATCHED"
                    except Exception:
                        status = "UNVERIFIED"

                vulns.append({
                    "plugin":   slug,
                    "version":  installed_ver or "unknown",
                    "status":   status,
                    **v,
                    "note": f"Installed: {installed_ver or 'unknown'} | Fixed in: {fixed_in}"
                })
    return vulns


# ══════════════════════════════════════════════════════════════════
#  PRETTY PRINT REPORT
# ══════════════════════════════════════════════════════════════════
def print_report(data):
    r = data["results"]

    # Server info
    section("Server & Technology Fingerprint", "🖥")
    sv = r.get("server_info", {})
    if sv.get("server"):       info(f"Server:         {sv['server']}")
    if sv.get("x_powered_by"): warn(f"X-Powered-By:   {sv['x_powered_by']}")
    if sv.get("php_version"):  warn(f"PHP Version:    {sv['php_version']}")
    if sv.get("protocol"):     info(f"Protocol:       {sv['protocol']}")
    if sv.get("waf_cdn"):      good(f"WAF / CDN:      {', '.join(sv['waf_cdn'])}")
    if sv.get("ssl_issuer"):   info(f"SSL Issuer:     {sv.get('ssl_issuer', {}).get('O', '')}")
    if sv.get("ssl_expires"):  info(f"SSL Expires:    {sv['ssl_expires']}")
    if sv.get("response_time_ms"): info(f"Response time:  {sv['response_time_ms']}ms")
    tech = sv.get("technologies", [])
    if tech: info(f"Technologies:   {', '.join(tech)}")
    if sv.get("cookies"):      info(f"Cookies:        {', '.join(sv['cookies'].keys())}")

    # REST API
    section("REST API Info", "🔗")
    api = r.get("rest_api", {})
    if api.get("name"):        info(f"Site name:      {api['name']}")
    if api.get("description"): info(f"Description:    {api['description']}")
    if api.get("timezone"):    info(f"Timezone:       {api['timezone']}")
    if api.get("wp_version"):  warn(f"WP version (API):{api['wp_version']}")
    if api.get("namespaces"):  info(f"Namespaces:     {', '.join(api['namespaces'][:8])}")
    if api.get("route_count"): info(f"API Routes:     {api['route_count']} total")

    # WP Version
    section("WordPress Version", "🔢")
    versions = r.get("wp_version", {})
    if versions:
        for src, ver in versions.items():
            warn(f"Version {ver}  (from {src})")
    else:
        good("Version not publicly exposed")

    # Users
    section("Users / Admins", "👤")
    users = r.get("users", [])
    if users:
        for u in users:
            bad(f"ID={u['id']}  login={u['login']}  name=\"{u['name']}\"  [{u['source']}]")
            if u.get("url"):    dim(f"         Profile: {u['url']}")
            if u.get("avatar"): dim(f"         Avatar:  {u['avatar']}")
    else:
        good("No users enumerated")

    # Emails
    section("Email Addresses Found", "📧")
    emails = r.get("emails", [])
    if emails:
        for e in emails:
            warn(f"{e['email']}  [{e['context']} — {e['source']}]")
    else:
        good("No emails found")

    # Social / contact
    section("Social Media & Phone Numbers", "🌐")
    social = r.get("social_contact", {})
    for platform, handles in social.get("social_media", {}).items():
        info(f"{platform}: {', '.join(handles)}")
    for phone in social.get("phones", []):
        info(f"Phone: {phone}")

    # Site structure
    section("Site Structure", "🗺")
    struct = r.get("structure", {})
    pages = struct.get("pages", [])
    if pages:
        info(f"Pages ({len(pages)}):")
        for p in pages[:15]:
            dim(f"  [{p.get('status','?')}] {p.get('title','')} → {p.get('url','')}")
    posts = struct.get("posts", [])
    if posts:
        info(f"Recent posts ({len(posts)}):")
        for p in posts[:5]:
            dim(f"  {p.get('date','')[:10]}  {p.get('title','')}")
    cats = struct.get("categories", [])
    if cats:
        info(f"Categories: {', '.join(c['name'] for c in cats[:10])}")
    tags = struct.get("tags", [])
    if tags:
        info(f"Tags ({len(tags)}): {', '.join(t['name'] for t in tags[:10])}")
    cpts = struct.get("custom_post_types", [])
    if cpts:
        info(f"Custom post types: {', '.join(c['slug'] for c in cpts)}")
    menus = struct.get("menus", [])
    if menus:
        info(f"Menus: {', '.join(m['name'] for m in menus)}")

    # Plugins
    section(f"Plugins Detected ({len(r.get('plugins',[]))})", "🔌")
    for p in r.get("plugins", []):
        ver = p.get("version") or "unknown"
        src = p.get("source", "")
        name = p.get("name") or p.get("slug")
        warn(f"{name} ({p['slug']})  v{ver}  [{src}]")
        if p.get("description"): dim(f"    {p['description']}")

    # Themes
    section("Themes", "🎨")
    for t in r.get("themes", []):
        name = t.get("name") or t["slug"]
        info(f"{name} ({t['slug']})  v{t.get('version','?')}  by {t.get('author','?')}")
        if t.get("template"): dim(f"    Parent theme: {t['template']}")

    # Vulnerabilities
    section("Known Vulnerabilities (Plugin CVE Correlation)", "⚠️")
    vulns = r.get("vulnerabilities", [])
    if vulns:
        for v in vulns:
            st = v.get("status", "UNVERIFIED")
            if st == "VULNERABLE":
                bad(f"[{st}] {v['plugin']} — {v['cve']} [{v['severity']}]")
                dim(f"    {v['desc']}")
                dim(f"    Fixed in: {v['fixed_in']}  |  Installed: {v['version']}")
            elif st == "PATCHED":
                good(f"[{st}] {v['plugin']} — {v['cve']} (Installed: {v['version']} >= Fixed: {v['fixed_in']})")
            else:
                warn(f"[{st}] {v['plugin']} — {v['cve']} [{v['severity']}] (Installed: {v['version']}, Fixed in: {v['fixed_in']})")
                dim(f"    {v['desc']}")
    else:
        good("No known CVEs matched detected plugins")

    # Security checks
    section("Security Checks", "🔒")
    sec = r.get("security", {})
    for path_info in sec.get("exposures", []):
        st = path_info["status"]
        label = path_info["label"]
        path  = path_info["path"]
        size  = path_info["size"]
        if st == 200:
            bad(f"[{st}] {label:35s} {path}  ({size} bytes)")
        else:
            warn(f"[{st}] {label:35s} {path}")

    print(f"\n  {C.BOLD}HTTP Security Headers:{C.RESET}")
    for header, val in sec.get("headers", {}).items():
        if val == "MISSING":
            warn(f"MISSING  {header}")
        else:
            good(f"Present  {header}: {val[:80]}")

    # Executive Security Posture Score
    score_info = data.get("security_score") or calculate_security_score(data)
    section("Executive Security Posture Score", "🛡")
    score = score_info["score"]
    grade = score_info["grade"]
    rating = score_info["rating"]
    col = C.GREEN if grade in ("A", "B") else (C.YELLOW if grade == "C" else C.RED)
    print(f"  {C.BOLD}Overall Score:{C.RESET}  {col}{C.BOLD}{score}/100 [Grade {grade}]{C.RESET} — {rating}")
    if score_info.get("deductions"):
        print(f"\n  {C.BOLD}Security Findings & Deductions:{C.RESET}")
        for d in score_info["deductions"]:
            print(f"    {C.YELLOW}•{C.RESET} {d}")


# ══════════════════════════════════════════════════════════════════
#  SECURITY RISK SCORE ENGINE
# ══════════════════════════════════════════════════════════════════
def calculate_security_score(report):
    score = 100
    deductions = []
    r = report.get("results", {})

    # 1. Vulnerable plugin CVEs
    vulns = r.get("vulnerabilities", [])
    for v in vulns:
        if v.get("status") == "VULNERABLE":
            sev = v.get("severity", "HIGH").upper()
            penalty = 20 if sev == "CRITICAL" else (15 if sev == "HIGH" else 8)
            score -= penalty
            deductions.append(f"Vulnerable plugin: {v.get('plugin')} ({v.get('cve')}) [{sev}] [-{penalty} pts]")

    # 2. Exposed sensitive paths
    exposures = r.get("security", {}).get("exposures", [])
    for exp in exposures:
        if exp.get("status") == 200:
            path = exp.get("path", "")
            if any(k in path for k in [".env", ".git", "wp-config", "db.sql", "backup"]):
                score -= 15
                deductions.append(f"Critical file disclosure: {path} [-15 pts]")
            elif "debug.log" in path:
                score -= 10
                deductions.append(f"Debug log file publicly accessible: {path} [-10 pts]")
            elif "xmlrpc.php" in path:
                score -= 5
                deductions.append("XML-RPC endpoint enabled [-5 pts]")

    # 3. Missing security headers
    headers = r.get("security", {}).get("headers", {})
    critical_headers = ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options"]
    missing = [h for h in critical_headers if headers.get(h) == "MISSING"]
    if missing:
        penalty = len(missing) * 3
        score -= penalty
        deductions.append(f"Missing {len(missing)} critical security headers ({', '.join(missing)}) [-{penalty} pts]")

    # 4. User enumeration exposed
    users = r.get("users", [])
    if len(users) > 0:
        score -= 5
        deductions.append(f"Public user/admin enumeration enabled ({len(users)} users revealed) [-5 pts]")

    # 5. WP core version exposed
    if r.get("wp_version"):
        score -= 5
        deductions.append("WordPress core version publicly disclosed [-5 pts]")

    score = max(0, min(100, score))

    if score >= 90:
        grade = "A"
        rating = "Excellent Posture"
    elif score >= 80:
        grade = "B"
        rating = "Good (Minor Hardening Needed)"
    elif score >= 65:
        grade = "C"
        rating = "Moderate Risk (Action Recommended)"
    elif score >= 50:
        grade = "D"
        rating = "High Risk (Vulnerabilities Found)"
    else:
        grade = "F"
        rating = "Critical Risk (Immediate Remediation Required)"

    return {
        "score": score,
        "grade": grade,
        "rating": rating,
        "deductions": deductions
    }


# ══════════════════════════════════════════════════════════════════
#  INTERACTIVE HTML REPORT GENERATOR
# ══════════════════════════════════════════════════════════════════
def generate_html_report(report, output_file):
    import html
    
    def esc(val):
        return html.escape(str(val)) if val is not None else ""
        
    target = report.get("target", "Target")
    scanned_at = report.get("scanned_at", str(datetime.now()))
    r = report.get("results", {})
    score_info = report.get("security_score") or calculate_security_score(report)
    
    score = score_info.get("score", 100)
    grade = score_info.get("grade", "A")
    rating = score_info.get("rating", "Good")
    deductions = score_info.get("deductions", [])
    
    plugins = r.get("plugins", [])
    vulns = r.get("vulnerabilities", [])
    active_vulns = [v for v in vulns if v.get("status") == "VULNERABLE"]
    users = r.get("users", [])
    exposures = r.get("security", {}).get("exposures", [])
    open_exposures = [e for e in exposures if e.get("status") == 200]
    headers = r.get("security", {}).get("headers", {})
    missing_headers = [k for k, v in headers.items() if v == "MISSING"]
    server_info = r.get("server_info", {})
    themes = r.get("themes", [])
    emails = r.get("emails", [])
    social = r.get("social_contact", {})

    grade_color = "#10b981" if grade in ("A", "B") else ("#f59e0b" if grade == "C" else "#ef4444")

    deductions_html = ""
    if deductions:
        deductions_html = '<div class="deductions-box"><h4>Security Findings & Penalties</h4><ul>'
        for d in deductions:
            deductions_html += f"<li>{esc(d)}</li>"
        deductions_html += "</ul></div>"

    vulns_html = ""
    if vulns:
        for v in vulns:
            st = v.get("status", "UNVERIFIED")
            sev = v.get("severity", "HIGH").upper()
            st_class = "badge-danger" if st == "VULNERABLE" else ("badge-success" if st == "PATCHED" else "badge-warning")
            sev_class = "badge-danger" if sev in ("CRITICAL", "HIGH") else "badge-warning"
            vulns_html += f"""
            <tr>
                <td><strong>{esc(v.get('plugin'))}</strong></td>
                <td><span class="badge badge-cve">{esc(v.get('cve'))}</span></td>
                <td><span class="badge {sev_class}">{esc(sev)}</span></td>
                <td><span class="badge {st_class}">{esc(st)}</span></td>
                <td>{esc(v.get('desc'))}</td>
                <td>Fixed in: <code>{esc(v.get('fixed_in'))}</code><br><small class="text-muted">Detected: {esc(v.get('version'))}</small></td>
            </tr>"""
    else:
        vulns_html = '<tr><td colspan="6" style="text-align: center; color: #10b981; padding: 24px;">No known CVEs matched detected plugins.</td></tr>'

    exp_html = ""
    if exposures:
        for exp in exposures:
            st = exp.get("status")
            badge_class = "badge-danger" if st == 200 else "badge-warning"
            exp_html += f"""
            <tr>
                <td><strong>{esc(exp.get('label'))}</strong></td>
                <td><code>{esc(exp.get('path'))}</code></td>
                <td><span class="badge {badge_class}">HTTP {st}</span></td>
                <td>{exp.get('size', 0):,} bytes</td>
            </tr>"""
    else:
        exp_html = '<tr><td colspan="4" style="text-align: center; color: #10b981; padding: 24px;">No sensitive paths exposed.</td></tr>'

    headers_html = ""
    for hname, hval in headers.items():
        is_missing = hval == "MISSING"
        badge = '<span class="badge badge-danger">MISSING</span>' if is_missing else '<span class="badge badge-success">PRESENT</span>'
        val_disp = esc(hval[:60] + "..." if len(str(hval)) > 60 else hval) if not is_missing else '<span class="text-muted">Not configured</span>'
        headers_html += f"""
        <div class="header-card {'border-missing' if is_missing else 'border-present'}">
            <div class="header-title"><span>{esc(hname)}</span>{badge}</div>
            <div class="header-val">{val_disp}</div>
        </div>"""

    users_html = ""
    if users:
        for u in users:
            users_html += f"""
            <tr>
                <td>{esc(u.get('id'))}</td>
                <td><strong>{esc(u.get('login'))}</strong></td>
                <td>{esc(u.get('name'))}</td>
                <td><span class="badge badge-info">{esc(u.get('source'))}</span></td>
                <td>{f'<a href="{esc(u.get("url"))}" target="_blank" style="color: var(--cyan);">Profile Link</a>' if u.get("url") else '<span class="text-muted">—</span>'}</td>
            </tr>"""
    else:
        users_html = '<tr><td colspan="5" style="text-align: center; color: #10b981; padding: 24px;">No usernames publicly revealed.</td></tr>'

    plugins_html = ""
    if plugins:
        for p in plugins:
            ver = p.get("version") or "unknown"
            plugins_html += f"""
            <tr>
                <td><strong>{esc(p.get('name') or p.get('slug'))}</strong> <code>({esc(p.get('slug'))})</code></td>
                <td><span class="badge badge-info">v{esc(ver)}</span></td>
                <td><small class="text-muted">{esc(p.get('source'))}</small></td>
                <td><small>{esc(p.get('description') or '—')}</small></td>
            </tr>"""
    else:
        plugins_html = '<tr><td colspan="4" style="text-align: center; color: #9ca3af; padding: 24px;">No plugins detected.</td></tr>'

    tech_list = server_info.get("technologies", [])
    tech_badges = "".join(f'<span class="badge badge-tech">{esc(t)}</span>' for t in tech_list) if tech_list else '<span class="text-muted">None detected</span>'
    waf_list = server_info.get("waf_cdn", [])
    waf_badges = "".join(f'<span class="badge badge-info">{esc(w)}</span>' for w in waf_list) if waf_list else '<span class="text-muted">None detected</span>'

    email_items = "".join(f'<li><strong>{esc(e.get("email"))}</strong> <small class="text-muted">({esc(e.get("context"))})</small></li>' for e in emails) or '<li class="text-muted">No emails discovered</li>'
    social_items = ""
    for plat, handles in social.get("social_media", {}).items():
        social_items += f'<li><strong>{esc(plat)}:</strong> {esc(", ".join(handles))}</li>'
    if not social_items:
        social_items = '<li class="text-muted">No social links discovered</li>'

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VexoraWP Audit Report — {esc(target)}</title>
<style>
:root {{
    --bg: #0b0f19;
    --card: #131b2e;
    --border: #1f2d47;
    --text: #f1f5f9;
    --text-muted: #94a3b8;
    --cyan: #06b6d4;
    --green: #10b981;
    --red: #ef4444;
    --yellow: #f59e0b;
    --blue: #3b82f6;
    --purple: #8b5cf6;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
    background-color: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    line-height: 1.5;
    padding: 32px 24px;
}}
.container {{ max-width: 1200px; margin: 0 auto; }}
.header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid var(--border);
    padding-bottom: 24px;
    margin-bottom: 32px;
}}
.brand {{ font-size: 28px; font-weight: 800; color: var(--cyan); letter-spacing: -0.5px; }}
.brand small {{ font-size: 13px; font-weight: 400; color: var(--text-muted); display: block; }}
.target-badge {{
    background: #1e293b;
    border: 1px solid var(--border);
    padding: 8px 16px;
    border-radius: 8px;
    text-align: right;
}}
.target-badge .url {{ font-family: monospace; font-size: 14px; color: var(--cyan); }}
.target-badge .time {{ font-size: 12px; color: var(--text-muted); display: block; }}

.kpi-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px;
    margin-bottom: 32px;
}}
.kpi-card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px;
    position: relative;
    overflow: hidden;
}}
.kpi-card .label {{ font-size: 12px; text-transform: uppercase; color: var(--text-muted); font-weight: 600; letter-spacing: 0.5px; }}
.kpi-card .value {{ font-size: 32px; font-weight: 800; margin-top: 4px; }}
.kpi-score {{ border-left: 4px solid {grade_color}; }}
.score-badge {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 6px;
    font-size: 14px;
    margin-left: 8px;
    background: {grade_color}22;
    color: {grade_color};
    border: 1px solid {grade_color}66;
}}

.section-title {{
    font-size: 20px;
    font-weight: 700;
    margin: 36px 0 16px;
    display: flex;
    align-items: center;
    gap: 8px;
}}
.card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 24px;
}}
.deductions-box {{
    background: rgba(245, 158, 11, 0.08);
    border: 1px solid rgba(245, 158, 11, 0.3);
    border-radius: 8px;
    padding: 16px;
    margin-top: 16px;
}}
.deductions-box h4 {{ color: var(--yellow); font-size: 14px; margin-bottom: 8px; }}
.deductions-box ul {{ list-style-position: inside; font-size: 13px; color: var(--text); }}
.deductions-box li {{ margin-bottom: 4px; }}

table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
}}
th, td {{
    padding: 12px 14px;
    text-align: left;
    border-bottom: 1px solid var(--border);
}}
th {{
    background: #0f172a;
    color: var(--text-muted);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}}
tr:last-child td {{ border-bottom: none; }}
tr:hover td {{ background: rgba(255,255,255,0.02); }}
code {{ font-family: monospace; color: var(--cyan); background: #0f172a; padding: 2px 6px; border-radius: 4px; }}

.badge {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 9999px;
    font-size: 11px;
    font-weight: 600;
}}
.badge-danger {{ background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }}
.badge-warning {{ background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); }}
.badge-success {{ background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); }}
.badge-info {{ background: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.4); }}
.badge-cve {{ background: rgba(139, 92, 246, 0.15); color: #c084fc; border: 1px solid rgba(139, 92, 246, 0.4); font-family: monospace; }}
.badge-tech {{ background: #1e293b; color: var(--cyan); border: 1px solid var(--border); margin: 2px 4px 2px 0; padding: 4px 10px; }}
.text-muted {{ color: var(--text-muted); }}

.headers-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 12px;
}}
.header-card {{
    background: #0f172a;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 12px 14px;
}}
.header-card.border-missing {{ border-left: 3px solid var(--red); }}
.header-card.border-present {{ border-left: 3px solid var(--green); }}
.header-title {{ display: flex; justify-content: space-between; align-items: center; font-size: 12px; font-weight: 600; margin-bottom: 4px; }}
.header-val {{ font-size: 11px; font-family: monospace; color: var(--text-muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}

.grid-2col {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
}}
@media (max-width: 768px) {{
    .grid-2col {{ grid-template-columns: 1fr; }}
    .header {{ flex-direction: column; align-items: flex-start; gap: 16px; }}
    .target-badge {{ text-align: left; width: 100%; }}
}}
ul.clean-list {{ list-style: none; }}
ul.clean-list li {{ padding: 6px 0; border-bottom: 1px solid var(--border); font-size: 13px; }}
ul.clean-list li:last-child {{ border-bottom: none; }}
.footer {{ text-align: center; margin-top: 48px; color: var(--text-muted); font-size: 12px; border-top: 1px solid var(--border); padding-top: 24px; }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <div class="brand">
            VexoraWP
            <small>WordPress Reconnaissance & Security Audit Suite</small>
        </div>
        <div class="target-badge">
            <span class="url">{esc(target)}</span>
            <span class="time">Audited: {esc(scanned_at)}</span>
        </div>
    </div>

    <div class="kpi-grid">
        <div class="kpi-card kpi-score">
            <div class="label">Security Score</div>
            <div class="value" style="color: {grade_color};">{score}<small style="font-size: 16px; color: var(--text-muted);">/100</small> <span class="score-badge">Grade {esc(grade)}</span></div>
            <small style="color: {grade_color}; font-weight: 600;">{esc(rating)}</small>
        </div>
        <div class="kpi-card">
            <div class="label">Known Vulnerabilities</div>
            <div class="value" style="color: {'var(--red)' if len(active_vulns) > 0 else 'var(--green)'};">{len(active_vulns)}</div>
            <small class="text-muted">{len(vulns)} total CVE matches evaluated</small>
        </div>
        <div class="kpi-card">
            <div class="label">Exposed Sensitive Files</div>
            <div class="value" style="color: {'var(--red)' if len(open_exposures) > 0 else 'var(--green)'};">{len(open_exposures)}</div>
            <small class="text-muted">{len(exposures)} sensitive probes active</small>
        </div>
        <div class="kpi-card">
            <div class="label">Enumerated Users</div>
            <div class="value" style="color: {'var(--yellow)' if len(users) > 0 else 'var(--green)'};">{len(users)}</div>
            <small class="text-muted">Public author/user leaks</small>
        </div>
        <div class="kpi-card">
            <div class="label">Missing Headers</div>
            <div class="value" style="color: {'var(--yellow)' if len(missing_headers) > 0 else 'var(--green)'};">{len(missing_headers)}</div>
            <small class="text-muted">Security headers unconfigured</small>
        </div>
    </div>

    {deductions_html}

    <div class="section-title">⚠️ Known Vulnerability Intelligence</div>
    <div class="card" style="padding: 0; overflow-x: auto;">
        <table>
            <thead>
                <tr>
                    <th>Plugin</th>
                    <th>CVE</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Description</th>
                    <th>Remediation</th>
                </tr>
            </thead>
            <tbody>
                {vulns_html}
            </tbody>
        </table>
    </div>

    <div class="section-title">🔒 Sensitive Path & Exposure Checks</div>
    <div class="card" style="padding: 0; overflow-x: auto;">
        <table>
            <thead>
                <tr>
                    <th>Asset Label</th>
                    <th>Path</th>
                    <th>Status</th>
                    <th>Content Size</th>
                </tr>
            </thead>
            <tbody>
                {exp_html}
            </tbody>
        </table>
    </div>

    <div class="section-title">🛡 HTTP Security Headers Evaluation</div>
    <div class="card">
        <div class="headers-grid">
            {headers_html}
        </div>
    </div>

    <div class="grid-2col">
        <div>
            <div class="section-title">🖥 Server & Technology Fingerprint</div>
            <div class="card">
                <table style="font-size: 13px;">
                    <tr><td class="text-muted" style="width: 140px;">Web Server</td><td><strong>{esc(server_info.get('server') or 'Unknown')}</strong></td></tr>
                    <tr><td class="text-muted">X-Powered-By</td><td>{esc(server_info.get('x_powered_by') or 'Hidden')}</td></tr>
                    <tr><td class="text-muted">PHP Version</td><td>{esc(server_info.get('php_version') or 'Not disclosed')}</td></tr>
                    <tr><td class="text-muted">WAF / CDN</td><td>{waf_badges}</td></tr>
                    <tr><td class="text-muted">SSL Issuer</td><td>{esc(server_info.get('ssl_issuer', {}).get('O') or '—')}</td></tr>
                    <tr><td class="text-muted">SSL Expiry</td><td>{esc(server_info.get('ssl_expires') or '—')}</td></tr>
                    <tr><td class="text-muted">Technologies</td><td>{tech_badges}</td></tr>
                </table>
            </div>
        </div>

        <div>
            <div class="section-title">👤 User & Admin Enumeration</div>
            <div class="card" style="padding: 0; overflow-x: auto;">
                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Username</th>
                            <th>Display Name</th>
                            <th>Vector</th>
                            <th>Link</th>
                        </tr>
                    </thead>
                    <tbody>
                        {users_html}
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <div class="grid-2col">
        <div>
            <div class="section-title">🔌 Detected Plugins ({len(plugins)})</div>
            <div class="card" style="padding: 0; max-height: 380px; overflow-y: auto;">
                <table>
                    <thead>
                        <tr>
                            <th>Plugin</th>
                            <th>Version</th>
                            <th>Source</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>
                        {plugins_html}
                    </tbody>
                </table>
            </div>
        </div>

        <div>
            <div class="section-title">🌐 Contacts & OSINT Discovery</div>
            <div class="card">
                <h4 style="font-size: 13px; color: var(--cyan); margin-bottom: 8px;">Harvested Emails</h4>
                <ul class="clean-list" style="margin-bottom: 20px;">
                    {email_items}
                </ul>
                <h4 style="font-size: 13px; color: var(--cyan); margin-bottom: 8px;">Social Media & Contact Channels</h4>
                <ul class="clean-list">
                    {social_items}
                </ul>
            </div>
        </div>
    </div>

    <div class="footer">
        Generated by <strong>VexoraWP</strong> — Passive WordPress Reconnaissance & Security Audit Suite
    </div>
</div>
</body>
</html>"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)


# ══════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════
def main():
    banner()
    parser = argparse.ArgumentParser(
        description="VexoraWP — Passive WordPress Reconnaissance & Security Audit Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("url",          help="Target WordPress site URL")
    parser.add_argument("-o","--output",help="Save JSON report to file",  default=None)
    parser.add_argument("--html",       help="Save interactive HTML audit report to file", default=None)
    parser.add_argument("--proxy",      help="HTTP/S proxy",              default=None)
    parser.add_argument("--ua",         help="Custom User-Agent",         default=None)
    parser.add_argument("--threads",    type=int, default=25,             help="Plugin probe threads (default: 25)")
    parser.add_argument("--timeout",    type=int, default=12,             help="HTTP timeout in seconds (default: 12)")
    parser.add_argument("--skip-plugins",  action="store_true", help="Skip plugin enumeration")
    parser.add_argument("--skip-emails",   action="store_true", help="Skip email harvesting")
    parser.add_argument("--skip-structure",action="store_true", help="Skip site structure mapping")
# ══════════════════════════════════════════════════════════════════
#  AUDIT ORCHESTRATOR (CLI & SERVERLESS ENTRYPOINT)
# ══════════════════════════════════════════════════════════════════
def run_audit(url, mode="full", threads=25, timeout=10, user_agent=None, proxy=None,
              skip_plugins=False, skip_emails=False, skip_structure=False):
    target = normalize(url)
    session = make_session(user_agent=user_agent, proxy=proxy, timeout=timeout, pool_size=max(50, threads * 2))

    signals = detect_wordpress(session, target)
    is_wp = bool(signals)

    report = {
        "target": target,
        "is_wordpress": is_wp,
        "signals": signals,
        "scanned_at": str(datetime.now()),
        "mode": mode,
        "results": {}
    }

    if not is_wp:
        report["error"] = f"WordPress not detected at {target}"
        return report

    R = report["results"]
    R["server_info"] = fingerprint_server(session, target)
    R["rest_api"] = probe_rest_api(session, target)
    R["wp_version"] = detect_wp_version(session, target)
    R["users"] = enumerate_users(session, target)

    if not skip_emails and mode == "full":
        R["emails"] = harvest_emails(session, target, max_pages=5)
        R["social_contact"] = extract_social_and_contact(session, target)
    else:
        R["emails"] = []
        R["social_contact"] = {"social_media": {}, "phones": []}

    if not skip_structure and mode == "full":
        R["structure"] = map_site_structure(session, target)
    else:
        R["structure"] = {}

    if not skip_plugins:
        actual_threads = threads if mode == "full" else min(threads, 15)
        R["plugins"] = enumerate_plugins(session, target, threads=actual_threads)
    else:
        R["plugins"] = []

    R["themes"] = enumerate_themes(session, target)
    R["vulnerabilities"] = lookup_vulnerabilities(R.get("plugins", []))
    R["security"] = {
        "exposures": check_exposures(session, target),
        "headers":   check_security_headers(session, target),
    }

    report["security_score"] = calculate_security_score(report)
    return report


# ══════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════
def main():
    banner()
    parser = argparse.ArgumentParser(
        description="VexoraWP — Passive WordPress Reconnaissance & Security Audit Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("url",          help="Target WordPress site URL")
    parser.add_argument("-o","--output",help="Save JSON report to file",  default=None)
    parser.add_argument("--html",       help="Save interactive HTML audit report to file", default=None)
    parser.add_argument("--proxy",      help="HTTP/S proxy",              default=None)
    parser.add_argument("--ua",         help="Custom User-Agent",         default=None)
    parser.add_argument("--threads",    type=int, default=25,             help="Plugin probe threads (default: 25)")
    parser.add_argument("--timeout",    type=int, default=12,             help="HTTP timeout in seconds (default: 12)")
    parser.add_argument("--skip-plugins",  action="store_true", help="Skip plugin enumeration")
    parser.add_argument("--skip-emails",   action="store_true", help="Skip email harvesting")
    parser.add_argument("--skip-structure",action="store_true", help="Skip site structure mapping")
    args = parser.parse_args()

    target  = normalize(args.url)
    print(f"  {C.BOLD}Target:{C.RESET}  {target}")
    print(f"  {C.BOLD}Time:{C.RESET}    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  {C.YELLOW}[!] Only scan sites you own or have written permission to audit.{C.RESET}\n")

    print(f"{C.BOLD}[*] Starting audit...{C.RESET}")
    report = run_audit(
        target,
        mode="full",
        threads=args.threads,
        timeout=args.timeout,
        user_agent=args.ua,
        proxy=args.proxy,
        skip_plugins=args.skip_plugins,
        skip_emails=args.skip_emails,
        skip_structure=args.skip_structure
    )

    if not report.get("is_wordpress"):
        bad(f"WordPress not detected at {target}")
        sys.exit(1)

    good(f"WordPress confirmed ({', '.join(report.get('signals', [])[:3])})")

    # ── Print ─────────────────────────────────────────────────────
    print_report(report)

    # ── Save JSON ─────────────────────────────────────────────────
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
        good(f"\nJSON report saved → {args.output}")

    # ── Save HTML ─────────────────────────────────────────────────
    if args.html:
        generate_html_report(report, args.html)
        good(f"Interactive HTML report saved → {args.html}")

    print(f"\n{C.BOLD}{C.GREEN}Scan complete.{C.RESET}\n")


if __name__ == "__main__":
    main()
