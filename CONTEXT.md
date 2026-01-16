# Project Context

## Overview

Pi-hole Dynamic Blocklist Generator - A Python script that fetches blocklists from seed URLs, parses multiple formats, categorizes domains, and produces consolidated and per-category blocklists suitable for Pi-hole.

## Project Structure

```
/home/erebustn/Documents/list creator/
├── list.txt                    # Seed URLs (39 unique blocklist sources)
├── pihole_list_creator.py     # Main generator script
├── config.json                # Configuration file
├── requirements.txt           # Python dependencies
├── README.md                  # Documentation
├── CONTEXT.md                 # This file
├── whitelist.txt              # Optional domain whitelist
├── blacklist.txt              # Generated output (domains only)
├── updater.log                # Activity log
└── categories/                # Per-category outputs (auto-created)
    ├── spam.txt
    ├── suspicious.txt
    ├── advertising.txt
    ├── tracking.txt
    ├── malicious.txt
    ├── porn.txt
    └── gambling.txt
```

## Blocklist Format Support

The script auto-detects and parses:

1. **Hosts file format**: `0.0.0.0 domain.com` or `127.0.0.1 domain.com`
2. **Domain-per-line**: Simple list of domains
3. **AdBlock rules**: `||domain.com^` style filters

## Categorization Logic

1. **URL-based hints**: If seed URL contains keywords (e.g., "phishing" → malicious)
2. **Domain keyword matching**: Against `category_rules` in config
3. **Suspiciousness score**: Long labels, high digit ratio, unusual TLDs

## Key Features

- Atomic file writes (prevents corruption)
- Thread-safe domain storage
- Configurable retry with exponential backoff
- Optional TCP connectivity checks
- Git auto-commit/push support

## Dependencies

- Python 3.8+
- requests >= 2.31.0
- beautifulsoup4 >= 4.12.0
- tldextract >= 5.1.0

## Quick Start

```bash
pip install -r requirements.txt
python pihole_list_creator.py --once
```
