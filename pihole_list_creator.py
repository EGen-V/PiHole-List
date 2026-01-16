#!/usr/bin/env python3
"""
Pi-hole Dynamic Blocklist Generator

Fetches blocklists from seed URLs, parses multiple formats (hosts files,
domain-per-line, AdBlock rules), categorizes domains, and produces consolidated
and per-category output files suitable for Pi-hole.
"""

import argparse
import json
import logging
import os
import re
import socket
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlparse

import requests
import tldextract
from bs4 import BeautifulSoup


# Default category order for consistent output
CATEGORY_ORDER = [
    "spam",
    "suspicious",
    "advertising",
    "tracking",
    "malicious",
    "porn",
    "gambling",
]

# URL path patterns for auto-categorization
URL_CATEGORY_PATTERNS: Dict[str, List[str]] = {
    "porn": ["porn", "adult", "nsfw", "xxx", "sex"],
    "gambling": ["gambling", "casino", "betting", "bet", "poker"],
    "malicious": ["phishing", "malware", "ransomware", "exploit", "threat", "abuse"],
    "tracking": ["tracking", "telemetry", "analytics", "spy", "fingerprint"],
    "advertising": ["ads", "adserver", "adguard", "adservice", "doubleclick", "banner"],
    "spam": ["spam", "junk"],
}


@dataclass
class FileStats:
    filename: str
    path: str
    description: str
    domains: int
    size_str: str


FILE_DESCRIPTIONS = {
    "blacklist.txt": "**Master list** — All domains combined",
    "advertising": "Ads, banners, ad networks",
    "tracking": "Analytics, telemetry, Smart TV trackers",
    "malicious": "Malware, phishing, scams",
    "porn": "Adult content",
    "gambling": "Casinos, betting sites",
    "spam": "Email spam, referrer spam",
    "suspicious": "Heuristically flagged domains",
}


def format_size(size_bytes: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} TB"


@dataclass(frozen=True)
class DomainHit:
    domain: str
    categories: Tuple[str, ...]
    source_url: str


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _version_stamp(dt: datetime) -> str:
    return dt.strftime("%Y.%m.%d.%H%M")


def _timestamp(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


def _read_lines(path: str) -> List[str]:
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f.readlines()]


def load_config(config_path: str) -> dict:
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)


def setup_logger(log_path: str) -> logging.Logger:
    logger = logging.getLogger("pihole_list_creator")
    logger.setLevel(logging.INFO)

    if logger.handlers:
        return logger

    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    return logger


# ============================================================================
# Domain Normalization & Validation
# ============================================================================


def is_valid_abs_http_url(url: str) -> bool:
    try:
        p = urlparse(url)
    except Exception:
        return False
    if p.scheme not in ("http", "https"):
        return False
    if not p.netloc:
        return False
    return True


def normalize_domain(domain: str) -> Optional[str]:
    """Normalize and validate a domain name."""
    d = (domain or "").strip().lower().rstrip(".")
    if not d:
        return None

    # Drop brackets for IPv6 literals if present
    if d.startswith("[") and d.endswith("]"):
        d = d[1:-1]

    # Reject obvious garbage
    if " " in d or "/" in d or "\t" in d:
        return None

    # Skip localhost and common local entries
    if d in ("localhost", "localhost.localdomain", "local", "broadcasthost"):
        return None

    # Domain or IP validation
    ip_ok = False
    try:
        socket.inet_pton(socket.AF_INET, d)
        ip_ok = True
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, d)
            ip_ok = True
        except OSError:
            ip_ok = False

    if ip_ok:
        # Skip loopback IPs
        if d.startswith("127.") or d == "0.0.0.0" or d == "::1":
            return None
        return d

    # Allow punycode, digits, hyphen, dot
    if not re.fullmatch(r"[a-z0-9.-]+", d):
        return None

    if d.startswith("-") or d.endswith("-"):
        return None

    if ".." in d:
        return None

    if "." not in d:
        return None

    return d


def extract_domain_from_url(url: str) -> Optional[str]:
    try:
        p = urlparse(url)
    except Exception:
        return None
    host = p.hostname
    if not host:
        return None
    return normalize_domain(host)


def domain_in_whitelist(domain: str, whitelist: Set[str]) -> bool:
    """Check if domain or any parent domain is whitelisted."""
    parts = domain.split(".")
    for i in range(len(parts)):
        candidate = ".".join(parts[i:])
        if candidate in whitelist:
            return True
    return False


# ============================================================================
# Blocklist Format Parsing
# ============================================================================


def parse_hosts_file(content: str) -> Set[str]:
    """
    Parse hosts file format:
    0.0.0.0 domain.com
    127.0.0.1 domain.com
    """
    domains: Set[str] = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Remove inline comments
        if "#" in line:
            line = line.split("#", 1)[0].strip()

        parts = line.split()
        if len(parts) < 2:
            continue

        # First part is IP, rest are domains
        ip = parts[0]
        # Validate it looks like an IP (rough check)
        if not re.match(r"^[\d.:a-fA-F]+$", ip):
            continue

        for domain in parts[1:]:
            d = normalize_domain(domain)
            if d:
                domains.add(d)

    return domains


def parse_domain_list(content: str) -> Set[str]:
    """
    Parse domain-per-line format.
    One domain per line, optionally with comments.
    """
    domains: Set[str] = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Remove inline comments
        if "#" in line:
            line = line.split("#", 1)[0].strip()

        # Skip if it looks like a hosts file entry
        if " " in line or "\t" in line:
            parts = line.split()
            if len(parts) >= 2 and re.match(r"^[\d.:]+$", parts[0]):
                # Looks like hosts format, extract domain
                for domain in parts[1:]:
                    d = normalize_domain(domain)
                    if d:
                        domains.add(d)
                continue

        d = normalize_domain(line)
        if d:
            domains.add(d)

    return domains


def parse_adblock_rules(content: str) -> Set[str]:
    """
    Parse AdBlock/uBlock filter rules to extract domains.
    Examples:
    ||ads.example.com^
    ||tracking.site.com^$third-party
    @@||allowed.com^  (exception rule - ignore)
    """
    domains: Set[str] = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("!") or line.startswith("["):
            continue

        # Skip exception rules
        if line.startswith("@@"):
            continue

        # Match ||domain^ pattern
        match = re.match(r"^\|\|([a-z0-9.-]+)\^", line, re.IGNORECASE)
        if match:
            d = normalize_domain(match.group(1))
            if d:
                domains.add(d)

    return domains


def detect_and_parse_blocklist(content: str) -> Set[str]:
    """
    Auto-detect blocklist format and parse domains.
    """
    lines = content.splitlines()
    non_empty_lines = [l.strip() for l in lines if l.strip() and not l.strip().startswith("#") and not l.strip().startswith("!")]

    if not non_empty_lines:
        return set()

    # Sample first few lines to detect format
    sample = non_empty_lines[:20]

    # Count patterns
    hosts_like = 0
    adblock_like = 0
    domain_like = 0

    for line in sample:
        if line.startswith("||") and "^" in line:
            adblock_like += 1
        elif re.match(r"^(0\.0\.0\.0|127\.0\.0\.1|::1?)\s+", line):
            hosts_like += 1
        elif re.match(r"^[a-z0-9.-]+$", line.lower()):
            domain_like += 1

    # Use format with highest count
    if adblock_like > hosts_like and adblock_like > domain_like:
        return parse_adblock_rules(content)
    elif hosts_like >= domain_like:
        return parse_hosts_file(content)
    else:
        return parse_domain_list(content)


# ============================================================================
# HTTP Utilities
# ============================================================================


def request_with_retry(
    session: requests.Session,
    url: str,
    timeout_seconds: int,
    max_retries: int,
    retry_backoff_seconds: float,
    max_redirects: int,
    logger: logging.Logger,
) -> Optional[requests.Response]:
    last_exc: Optional[Exception] = None

    for attempt in range(1, max_retries + 1):
        try:
            resp = session.get(
                url,
                timeout=timeout_seconds,
                allow_redirects=True,
            )
            if len(resp.history) > max_redirects:
                logger.info("Too many redirects (%s): %s", len(resp.history), url)
                return None
            if resp.status_code >= 400:
                logger.info("HTTP %s for %s", resp.status_code, url)
                return None
            return resp
        except Exception as e:
            last_exc = e
            logger.info("Request error (attempt %s/%s) %s: %s", attempt, max_retries, url, e)
            time.sleep(retry_backoff_seconds * attempt)

    if last_exc is not None:
        logger.info("Giving up on %s due to errors", url)
    return None


# ============================================================================
# Categorization
# ============================================================================


def categorize_from_url(url: str) -> Set[str]:
    """
    Infer categories from the URL path/name.
    """
    categories: Set[str] = set()
    url_lower = url.lower()

    for cat, patterns in URL_CATEGORY_PATTERNS.items():
        for pattern in patterns:
            if pattern in url_lower:
                categories.add(cat)
                break

    return categories


def categorize_domain(
    domain: str,
    rules: Dict[str, List[str]],
    url_cats: Set[str],
    suspicious: bool,
) -> Tuple[str, ...]:
    """
    Categorize a domain based on keyword matching and URL source hints.
    """
    cats: Set[str] = set(url_cats)

    for cat, keywords in rules.items():
        if cat == "suspicious":
            continue
        for kw in keywords:
            if kw and kw.lower() in domain:
                cats.add(cat)
                break

    if suspicious and "suspicious" not in cats:
        cats.add("suspicious")

    # Return ordered tuple
    ordered = [c for c in CATEGORY_ORDER if c in cats]
    return tuple(ordered) if ordered else ("suspicious",)


def suspicious_score(
    domain: str,
    heuristics: dict,
) -> int:
    """Calculate a suspiciousness score for a domain."""
    score = 0

    # Heuristic: very long labels
    label_len_thr = heuristics.get("label_length_threshold", 25)
    if any(len(lbl) >= label_len_thr for lbl in domain.split(".")):
        score += 1

    # Heuristic: digit ratio
    digits = sum(1 for c in domain if c.isdigit())
    ratio = digits / max(1, len(domain))
    if ratio >= heuristics.get("domain_digit_ratio_threshold", 0.35):
        score += 1

    # Heuristic: uncommon TLDs
    ext = tldextract.extract(domain)
    if ext.suffix and len(ext.suffix) >= 8:
        score += 1

    return score


def connectivity_check(domain: str, ports: List[int], timeout_seconds: float) -> bool:
    """Check if a domain is reachable on common ports."""
    for port in ports:
        try:
            with socket.create_connection((domain, port), timeout=timeout_seconds):
                return True
        except Exception:
            continue
    return False


# ============================================================================
# Output Generation
# ============================================================================


def build_header(version: str, entries: int, last_modified: str) -> str:
    """Generate a stylish header for the blocklist."""
    return "\n".join([
        "#",
        "# ╔═══════════════════════════════════════════════════════════════════════╗",
        "# ║                                                                       ║",
        "# ║   ███████╗██████╗ ███████╗██████╗ ██╗   ██╗███████╗████████╗███╗   ██╗║",
        "# ║   ██╔════╝██╔══██╗██╔════╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝████╗  ██║║",
        "# ║   █████╗  ██████╔╝█████╗  ██████╔╝██║   ██║███████╗   ██║   ██╔██╗ ██║║",
        "# ║   ██╔══╝  ██╔══██╗██╔══╝  ██╔══██╗██║   ██║╚════██║   ██║   ██║╚██╗██║║",
        "# ║   ███████╗██║  ██║███████╗██████╔╝╚██████╔╝███████║   ██║   ██║ ╚████║║",
        "# ║   ╚══════╝╚═╝  ╚═╝╚══════╝╚═════╝  ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═══╝║",
        "# ║                                                                       ║",
        "# ║                    🛡️  DYNAMIC BLOCKLIST  🛡️                          ║",
        "# ║                                                                       ║",
        "# ╚═══════════════════════════════════════════════════════════════════════╝",
        "#",
        "# ┌─────────────────────────────────────────────────────────────────────────┐",
        "# │                           LIST METADATA                                 │",
        "# ├─────────────────────────────────────────────────────────────────────────┤",
        f"# │  📋 Title      : ErebusTN Dynamic Blocklist                            │",
        f"# │  🔖 Version    : {version:<54}│",
        f"# │  📊 Entries    : {entries:<54}│",
        f"# │  🕐 Modified   : {last_modified:<54}│",
        "# │  ⏰ Expires    : 30 minutes                                            │",
        "# │  👤 Maintainer : ErebusTN                                              │",
        "# └─────────────────────────────────────────────────────────────────────────┘",
        "#",
        "# ┌─────────────────────────────────────────────────────────────────────────┐",
        "# │                           CATEGORIES                                    │",
        "# ├─────────────────────────────────────────────────────────────────────────┤",
        "# │  🚫 spam         │  ⚠️  suspicious   │  📢 advertising                   │",
        "# │  📡 tracking     │  ☠️  malicious    │  🔞 porn                          │",
        "# │  🎰 gambling     │                   │                                   │",
        "# └─────────────────────────────────────────────────────────────────────────┘",
        "#",
        "# 💡 Usage: Add this URL to Pi-hole → Adlists → Update Gravity",
        "# 🔗 Repository: https://github.com/EGen-V/PiHole-List-Creator",
        "#",
        "# ═══════════════════════════════════════════════════════════════════════════",
        "",
    ])


def read_existing_domains(output_path: str) -> Set[str]:
    if not os.path.exists(output_path):
        return set()

    domains: Set[str] = set()
    with open(output_path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            domains.add(s)
    return domains


MAX_FILE_SIZE = 90 * 1024 * 1024  # 90 MB limit to stay comfortably under GitHub's 100 MB


def atomic_write(path: str, content: str) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(content)
    os.replace(tmp, path)


def write_split_output(
    base_path: str,
    domains: List[str],
    version: str,
    last_modified: str,
    logger: logging.Logger
) -> List[str]:
    """
    Write domains to file(s), splitting if necessary.
    Returns list of generated file paths.
    """
    # Estimate size to decide if splitting is needed
    # Header is roughly 1KB, safe to ignore for rough estimation or add buffer
    total_estimated_size = sum(len(d) + 1 for d in domains) + 2000 
    
    generated_files = []

    if total_estimated_size < MAX_FILE_SIZE:
        # Fits in one file
        header = build_header(version=version, entries=len(domains), last_modified=last_modified)
        body = "\n".join(domains) + ("\n" if domains else "")
        atomic_write(base_path, header + body)
        generated_files.append(base_path)
        logger.info("Wrote %s entries to %s (%.1f MB)", len(domains), base_path, total_estimated_size / 1024 / 1024)
        
        # Cleanup potential old parts if we are now single file
        # (Naive cleanup: check .part1 and remove if exists? Or rely on git to handle deletions)
        # For safety/simplicity, we won't aggressively delete unrelated files, but we should probably
        # ensure we don't leave stale parts if we shrank.
        # User can handle cleanup or we can rely on git add -A.
    else:
        # Needs splitting
        logger.info("Output exceeds size limit; splitting into parts...")
        part_num = 1
        current_chunk = []
        current_size = 2000  # header buffer

        for d in domains:
            line_len = len(d) + 1  # +1 for newline
            if current_size + line_len > MAX_FILE_SIZE:
                # Flush current chunk
                part_path = f"{base_path}.part{part_num}"
                header = build_header(version=version, entries=len(current_chunk), last_modified=last_modified)
                body = "\n".join(current_chunk) + ("\n" if current_chunk else "")
                atomic_write(part_path, header + body)
                generated_files.append(part_path)
                logger.info("Wrote part %d: %s entries to %s", part_num, len(current_chunk), part_path)
                
                # Reset for next chunk
                part_num += 1
                current_chunk = []
                current_size = 2000

            current_chunk.append(d)
            current_size += line_len

        # Flush final chunk
        if current_chunk:
            part_path = f"{base_path}.part{part_num}"
            header = build_header(version=version, entries=len(current_chunk), last_modified=last_modified)
            body = "\n".join(current_chunk) + ("\n" if current_chunk else "")
            atomic_write(part_path, header + body)
            generated_files.append(part_path)
            logger.info("Wrote part %d: %s entries to %s", part_num, len(current_chunk), part_path)
            
        # If we split, we might want to ensure the base_path file (if it existed) is removed 
        # to avoid confusion, or keep it as a meta/pointer? 
        # Standard practice: if we have parts, we probably don't want the giant file.
        if os.path.exists(base_path):
            try:
                os.remove(base_path)
                logger.info("Removed original large file %s in favor of parts", base_path)
            except OSError:
                pass

    return generated_files


def write_blocklist(
    output_path: str,
    domains_sorted: List[str],
    logger: logging.Logger,
) -> Tuple[Set[str], Set[str]]:
    # We still need to calculate added/removed for logging/git message
    # This assumes we can read the old generic file OR parts.
    # For simplicity, we'll read 'all existing' by trying base path + parts.
    
    # Read existing
    prev = set()
    if os.path.exists(output_path):
        prev.update(read_existing_domains(output_path))
    
    # Check for parts
    part_num = 1
    while True:
        part_path = f"{output_path}.part{part_num}"
        if os.path.exists(part_path):
            prev.update(read_existing_domains(part_path))
            part_num += 1
        else:
            if part_num > 100: # Safety break
                break
            # If part 1 exists but part 2 doesn't, we stop. 
            # If we have gaps, we might miss some, but standard usage won't have gaps.
            if not os.path.exists(f"{output_path}.part{part_num}"): 
                 break

    new = set(domains_sorted)
    added = new - prev
    removed = prev - new

    now = _utc_now()
    version = _version_stamp(now)
    last_mod = _timestamp(now)

    write_split_output(output_path, domains_sorted, version, last_mod, logger)

    write_split_output(output_path, domains_sorted, version, last_mod, logger)

    if added:
        logger.info("Added %s domains (net change)", len(added))
    if removed:
        logger.info("Removed %s domains (net change)", len(removed))

    # Calculate stats for return
    stats = []
    # Check for parts or single file
    if os.path.exists(output_path):
        size = os.path.getsize(output_path)
        stats.append(FileStats(
            filename="blacklist.txt",
            path="blacklist.txt",
            description=FILE_DESCRIPTIONS.get("blacklist.txt", "Master list"),
            domains=len(domains_sorted),
            size_str=format_size(size)
        ))
    else:
        # Check parts
        part_num = 1
        total_domains_accounted = 0 # Rough distribution if needed, but we can assign full count to first or just "-"
        # Actually, user wants to know how many domains are in the list properly. 
        # But if split, the count per file differs. 
        # write_split_output doesn't return count per file currently. 
        # Let's simple check files.
        while True:
            p_path = f"{output_path}.part{part_num}"
            if not os.path.exists(p_path):
                break
            
            # We need domain count per part for accuracy? 
            # Or just list "See raw file" for domains? 
            # The current parsing logic in write_split_output writes chunks. 
            # To be accurate without re-reading, we should update write_split_output to return stats.
            # But for now, let's just use line count - header overhead approximately or re-read.
            # Re-reading is safest.
            p_domains = len(read_existing_domains(p_path))
            p_size = os.path.getsize(p_path)
            
            stats.append(FileStats(
                filename=f"blacklist.txt.part{part_num}",
                path=f"blacklist.txt.part{part_num}",
                description=f"{FILE_DESCRIPTIONS.get('blacklist.txt', 'Master list')} (Part {part_num})",
                domains=p_domains,
                size_str=format_size(p_size)
            ))
            part_num += 1

    return added, removed, stats


def write_category_files(
    output_dir: str,
    category_map: Dict[str, Set[str]],
    logger: logging.Logger,
) -> List[FileStats]:
    os.makedirs(output_dir, exist_ok=True)
    now = _utc_now()
    version = _version_stamp(now)
    last_mod = _timestamp(now)

    all_stats = []

    for cat in CATEGORY_ORDER:
        domains = sorted(category_map.get(cat, set()))
        path = os.path.join(output_dir, f"{cat}.txt")
        write_split_output(path, domains, version, last_mod, logger)
        
        # Gather stats
        desc = FILE_DESCRIPTIONS.get(cat, cat.capitalize())
        
        if os.path.exists(path):
            size = os.path.getsize(path)
            all_stats.append(FileStats(
                filename=f"categories/{cat}.txt",
                path=f"categories/{cat}.txt",
                description=desc,
                domains=len(domains),
                size_str=format_size(size)
            ))
        else:
            part_num = 1
            while True:
                p_path = f"{path}.part{part_num}"
                if not os.path.exists(p_path):
                    break
                
                p_domains = len(read_existing_domains(p_path))
                p_size = os.path.getsize(p_path)
                
                all_stats.append(FileStats(
                    filename=f"categories/{cat}.txt.part{part_num}",
                    path=f"categories/{cat}.txt.part{part_num}",
                    description=f"{desc} (Part {part_num})",
                    domains=p_domains,
                    size_str=format_size(p_size)
                ))
                part_num += 1
                
    return all_stats


# ============================================================================
# Git Integration
# ============================================================================


def git_commit_and_push(
    repo_path: str,
    message: str,
    remote: str,
    branch: str,
    logger: logging.Logger,
) -> None:
    def run(args: List[str]) -> None:
        subprocess.run(args, cwd=repo_path, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    try:
        run(["git", "add", "-A"])
        run(["git", "commit", "-m", message])
        run(["git", "push", remote, branch])
        logger.info("Pushed updates to %s/%s", remote, branch)
    except subprocess.CalledProcessError as e:
        stderr = ""
        try:
            stderr = e.stderr.decode("utf-8", errors="ignore")
        except Exception:
            pass
        # No changes to commit is okay
        if "nothing to commit" in stderr or "no changes" in stderr.lower():
            logger.info("No changes to commit")
        else:
            logger.info("Git push failed: %s", stderr or str(e))


# ============================================================================
# Domain Store (Thread-Safe) & Source Statistics
# ============================================================================


@dataclass
class SourceStats:
    """Track statistics for each source URL."""
    url: str
    total_domains: int = 0
    unique_domains: int = 0
    overlap_domains: int = 0
    fetch_time_ms: float = 0.0
    categories: Set[str] = field(default_factory=set)
    error: Optional[str] = None

    @property
    def overlap_pct(self) -> float:
        if self.total_domains == 0:
            return 0.0
        return (self.overlap_domains / self.total_domains) * 100

    @property
    def unique_pct(self) -> float:
        if self.total_domains == 0:
            return 0.0
        return (self.unique_domains / self.total_domains) * 100


class DomainStore:
    def __init__(self, logger: logging.Logger):
        self._lock = threading.Lock()
        self._domains: Dict[str, Set[str]] = {}  # domain -> categories
        self._logger = logger
        self._source_stats: List[SourceStats] = []

    def upsert(self, domain: str, categories: Iterable[str]) -> bool:
        """Insert domain. Returns True if new, False if already existed."""
        cats = set(categories)
        if not cats:
            return False
        with self._lock:
            existing = self._domains.get(domain)
            if existing is None:
                self._domains[domain] = set(cats)
                return True
            else:
                existing.update(cats)
                return False

    def add_source_stats(self, stats: SourceStats) -> None:
        with self._lock:
            self._source_stats.append(stats)

    def get_source_stats(self) -> List[SourceStats]:
        with self._lock:
            return list(self._source_stats)

    def snapshot(self) -> Dict[str, Set[str]]:
        with self._lock:
            return {d: set(c) for d, c in self._domains.items()}

    def dedupe_scan(self) -> None:
        pass

    def count(self) -> int:
        with self._lock:
            return len(self._domains)


# ============================================================================
# Main Generation Logic
# ============================================================================


def generate_once(config: dict, logger: logging.Logger, store: DomainStore) -> None:
    """
    Main generation cycle: fetch all seed URLs, parse as blocklists,
    categorize domains, and populate the store.
    """
    seed_list_path = config["seed_list_path"]
    whitelist_path = config.get("whitelist_path", "whitelist.txt")

    seeds = [s for s in _read_lines(seed_list_path) if s and not s.startswith("#")]
    whitelist = set(normalize_domain(x) for x in _read_lines(whitelist_path))
    whitelist.discard(None)

    logger.info("Loaded %s seed URLs, %s whitelist entries", len(seeds), len(whitelist))

    session = requests.Session()
    session.headers.update({"User-Agent": config.get("user_agent", "Mozilla/5.0")})

    rules = config.get("category_rules", {})
    heuristics = config.get("suspicious_heuristics", {})
    request_delay = float(config.get("request_delay_seconds", 0))
    do_connectivity = config.get("connectivity_check", False)  # Disabled by default for speed

    for seed in seeds:
        if not is_valid_abs_http_url(seed):
            logger.info("Skipping invalid seed URL: %s", seed)
            continue

        time.sleep(request_delay)

        resp = request_with_retry(
            session=session,
            url=seed,
            timeout_seconds=int(config.get("request_timeout_seconds", 15)),
            max_retries=int(config.get("max_retries", 3)),
            retry_backoff_seconds=float(config.get("retry_backoff_seconds", 2)),
            max_redirects=int(config.get("max_redirects", 10)),
            logger=logger,
        )
        if resp is None:
            continue

        # Infer categories from URL
        url_cats = categorize_from_url(seed)

        # Parse the blocklist content
        content = resp.text
        domains = detect_and_parse_blocklist(content)

        logger.info("Seed %s -> parsed %s domains (inferred categories: %s)", 
                   seed, len(domains), ", ".join(url_cats) if url_cats else "none")

        # Track stats for this source
        source_stats = SourceStats(url=seed, total_domains=len(domains), categories=url_cats)
        unique_count = 0
        overlap_count = 0

        for d in domains:
            if domain_in_whitelist(d, whitelist):
                continue

            # Calculate suspicious score
            score = suspicious_score(d, heuristics)
            suspicious = score >= 2

            # Optional connectivity check
            if do_connectivity:
                ok = connectivity_check(
                    d,
                    ports=[int(p) for p in config.get("connectivity_ports", [80, 443])],
                    timeout_seconds=float(config.get("connectivity_timeout_seconds", 2)),
                )
                if not ok:
                    suspicious = True

            cats = categorize_domain(d, rules=rules, url_cats=url_cats, suspicious=suspicious)
            is_new = store.upsert(d, cats)
            if is_new:
                unique_count += 1
            else:
                overlap_count += 1

        # Record stats
        source_stats.unique_domains = unique_count
        source_stats.overlap_domains = overlap_count
        store.add_source_stats(source_stats)

    logger.info("Total unique domains in store: %s", store.count())


def build_outputs(store_snapshot: Dict[str, Set[str]]) -> Tuple[List[str], Dict[str, Set[str]]]:
    all_domains = sorted(store_snapshot.keys())
    category_map: Dict[str, Set[str]] = {c: set() for c in CATEGORY_ORDER}

    for d, cats in store_snapshot.items():
        for c in cats:
            if c in category_map:
                category_map[c].add(d)

    return all_domains, category_map


def run_scheduler(config: dict, logger: logging.Logger) -> None:
    """Run continuous regeneration cycles."""
    stop_event = threading.Event()

    def dedupe_loop(store: DomainStore) -> None:
        interval = float(config.get("dedupe_scan_interval_seconds", 10))
        while not stop_event.is_set():
            try:
                store.dedupe_scan()
            except Exception as e:
                logger.info("Dedupe loop error: %s", e)
            stop_event.wait(interval)

    regen_interval = float(config.get("regeneration_interval_minutes", 30)) * 60.0

    while True:
        start = time.time()
        store = DomainStore(logger)

        # Start dedupe thread for this cycle
        t = threading.Thread(target=dedupe_loop, args=(store,), daemon=True)
        t.start()

        try:
            logger.info("Starting regeneration cycle")
            generate_once(config, logger, store)

            snapshot = store.snapshot()
            domains_sorted, category_map = build_outputs(snapshot)

            output_path = config.get("output_blacklist_path", "blacklist.txt")
            added, removed, bl_stats = write_blocklist(output_path, domains_sorted, logger)

            out_dir = config.get("output_category_dir", "categories")
            cat_stats = write_category_files(out_dir, category_map, logger)

            update_readme_stats(bl_stats + cat_stats, "README.md", logger)

            git_cfg = config.get("git", {})
            if git_cfg.get("enabled", False):
                now = _utc_now()
                msg = f"Update blacklist {_version_stamp(now)} (+{len(added)}/-{len(removed)})"
                git_commit_and_push(
                    repo_path=str(git_cfg.get("repo_path", ".")),
                    message=msg,
                    remote=str(git_cfg.get("remote", "origin")),
                    branch=str(git_cfg.get("branch", "main")),
                    logger=logger,
                )

        except Exception as e:
            logger.exception("Regeneration cycle failed: %s", e)

        stop_event.set()  # Stop dedupe thread
        elapsed = time.time() - start
        sleep_for = max(0.0, regen_interval - elapsed)
        logger.info("Cycle complete in %.1fs; sleeping %.1fs until next cycle", elapsed, sleep_for)
        
        # Reset for next cycle
        stop_event = threading.Event()
        time.sleep(sleep_for)


def print_source_stats_report(store: DomainStore, logger: logging.Logger) -> None:
    """Print a detailed source quality report."""
    stats = store.get_source_stats()
    if not stats:
        return

    print("\n" + "=" * 90)
    print("                           SOURCE QUALITY REPORT")
    print("=" * 90)
    print(f"{'Source URL':<55} {'Total':>8} {'Unique':>8} {'Overlap':>8} {'Overlap%':>8}")
    print("-" * 90)

    # Sort by overlap percentage (highest first)
    stats_sorted = sorted(stats, key=lambda x: x.overlap_pct, reverse=True)

    for s in stats_sorted:
        if s.error:
            print(f"{s.url[:54]:<55} {'ERROR':>8} {s.error[:30]}")
        else:
            url_short = s.url[:54] if len(s.url) <= 54 else s.url[:51] + "..."
            print(f"{url_short:<55} {s.total_domains:>8} {s.unique_domains:>8} {s.overlap_domains:>8} {s.overlap_pct:>7.1f}%")

    print("-" * 90)
    total_domains = sum(s.total_domains for s in stats if not s.error)
    unique_total = store.count()
    total_overlap = total_domains - unique_total
    print(f"{'TOTALS':<55} {total_domains:>8} {unique_total:>8} {total_overlap:>8} {(total_overlap/max(1,total_domains))*100:>7.1f}%")
    print("=" * 90)

    # Recommendations
    high_overlap = [s for s in stats if s.overlap_pct > 80 and s.total_domains > 100]
    if high_overlap:
        print("\n⚠️  HIGH OVERLAP SOURCES (>80% duplicate domains):")
        for s in high_overlap[:5]:
            print(f"   • {s.url[:70]}")
        print("   Consider removing these to reduce processing time.\n")


def update_readme_stats(stats: List[FileStats], readme_path: str, logger: logging.Logger) -> None:
    """Regenerate the 'Available Lists' table in README.md."""
    if not os.path.exists(readme_path):
        logger.warning("README.md not found, skipping stats update")
        return

    try:
        with open(readme_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        start_idx = -1
        end_idx = -1

        # Find the table bounds
        for i, line in enumerate(lines):
            if "| File | Description | Domains |" in line or "| File | Description | Domains | Size |" in line:
                start_idx = i
            elif start_idx != -1 and not line.strip().startswith("|") and i > start_idx + 1:
                end_idx = i
                break
        
        if start_idx == -1:
            logger.warning("Could not find table in README.md")
            return

        if end_idx == -1:
            end_idx = len(lines)

        # Generate new table
        new_table = []
        new_table.append("| File | Description | Domains | Size |\n")
        new_table.append("|------|-------------|---------|------|\n")
        
        for s in stats:
            # Markdown link
            link = f"[`{s.filename}`]({s.path})"
            new_table.append(f"| {link} | {s.description} | {s.domains:,} | {s.size_str} |\n")

        # Replace lines
        lines[start_idx:end_idx] = new_table

        with open(readme_path, "w", encoding="utf-8") as f:
            f.writelines(lines)
            
        logger.info("Updated README.md with new stats")

    except Exception as e:
        logger.exception("Failed to update README: %s", e)
        
    # Update "Last Update" timestamp
    try:
        now = _utc_now()
        date_str = now.strftime("%B %Y")
        
        updated_lines = []
        for line in lines:
            if line.strip().startswith("**Last Update:**"):
                updated_lines.append(f"**Last Update:** {date_str}\n")
            else:
                updated_lines.append(line)
        
        with open(readme_path, "w", encoding="utf-8") as f:
            f.writelines(updated_lines)
            
    except Exception as e:
        logger.exception("Failed to update timestamp in README: %s", e)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Pi-hole Dynamic Blocklist Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--config", default="config.json", help="Path to config file")
    parser.add_argument("--once", action="store_true", help="Run one regeneration cycle and exit")
    parser.add_argument("--test", action="store_true", help="Test mode: generate but don't write output files")
    parser.add_argument("--stats", action="store_true", help="Show source quality statistics after generation")
    args = parser.parse_args()

    config = load_config(args.config)
    logger = setup_logger(config.get("log_path", "updater.log"))

    logger.info("Pi-hole Blocklist Generator starting (config: %s)", args.config)

    if args.once or args.test:
        store = DomainStore(logger)
        mode = "TEST MODE" if args.test else "one-shot"
        logger.info("Running %s generation", mode)
        generate_once(config, logger, store)
        snapshot = store.snapshot()
        domains_sorted, category_map = build_outputs(snapshot)

        if args.stats or args.test:
            print_source_stats_report(store, logger)

        if not args.test:
            added, removed, bl_stats = write_blocklist(config.get("output_blacklist_path", "blacklist.txt"), domains_sorted, logger)
            cat_stats = write_category_files(config.get("output_category_dir", "categories"), category_map, logger)
            
            # Update README
            update_readme_stats(bl_stats + cat_stats, "README.md", logger)
            
            logger.info("One-shot generation complete")
        else:
            logger.info("TEST MODE: Skipped writing output files")
            print(f"\n✅ Test complete: {len(domains_sorted)} unique domains would be written")
        return

    run_scheduler(config, logger)


if __name__ == "__main__":
    main()
