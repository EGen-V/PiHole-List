# 🛡️ ErebusTN Pi-hole Blocklists

[![Domain Count](https://img.shields.io/badge/domains-6M+-blue)](https://github.com/EGen-V/PiHole-List)
[![Updated](https://img.shields.io/badge/updated-every%2030%20min-green)](https://github.com/EGen-V/PiHole-List)
[![License](https://img.shields.io/badge/license-public%20domain-lightgrey)](https://github.com/EGen-V/PiHole-List)

Curated DNS blocklists for Pi-hole, AdGuard Home, and other DNS-based ad blockers.

---

## 📋 Available Lists

| File | Description | Domains | Size |
|------|-------------|---------|------|
| [`blacklist.txt.part1`](https://raw.githubusercontent.com/EGen-V/PiHole-List/main/blacklist.txt.part1) | **Master list** — All domains combined (Part 1) | 3,820,130 | 90.00 MB |
| [`blacklist.txt.part2`](https://raw.githubusercontent.com/EGen-V/PiHole-List/main/blacklist.txt.part2) | **Master list** — All domains combined (Part 2) | 2,370,030 | 54.93 MB |
| [`categories/spam.txt`](https://raw.githubusercontent.com/EGen-V/PiHole-List/main/categories/spam.txt) | Email spam, referrer spam | 87,705 | 1.45 MB |
| [`categories/suspicious.txt`](https://raw.githubusercontent.com/EGen-V/PiHole-List/main/categories/suspicious.txt) | Heuristically flagged domains | 1,532,315 | 32.71 MB |
| [`categories/advertising.txt`](https://raw.githubusercontent.com/EGen-V/PiHole-List/main/categories/advertising.txt) | Ads, banners, ad networks | 628,685 | 14.67 MB |
| [`categories/tracking.txt`](https://raw.githubusercontent.com/EGen-V/PiHole-List/main/categories/tracking.txt) | Analytics, telemetry, Smart TV trackers | 748,607 | 19.47 MB |
| [`categories/malicious.txt`](https://raw.githubusercontent.com/EGen-V/PiHole-List/main/categories/malicious.txt) | Malware, phishing, scams | 1,671,931 | 38.76 MB |
| [`categories/porn.txt`](https://raw.githubusercontent.com/EGen-V/PiHole-List/main/categories/porn.txt) | Adult content | 2,501,058 | 60.80 MB |
| [`categories/gambling.txt`](https://raw.githubusercontent.com/EGen-V/PiHole-List/main/categories/gambling.txt) | Casinos, betting sites | 194,982 | 3.60 MB |


---

## 🚀 Quick Start

### Pi-hole

1. Go to **Group Management → Adlists**
2. Add the raw URLs:
   ```
   https://raw.githubusercontent.com/EGen-V/PiHole-List/main/blacklist.txt.part1
   https://raw.githubusercontent.com/EGen-V/PiHole-List/main/blacklist.txt.part2
   ```

3. Run **Tools → Update Gravity**

### AdGuard Home

1. Go to **Filters → DNS blocklists**
2. Click **Add blocklist → Add a custom list**
3. Add each part URL separately

---

## 📊 Sources

These lists aggregate and deduplicate domains from **100+ trusted sources** including:

| Source | Description |
|--------|-------------|
| [OISD](https://oisd.nl/) | Comprehensive mega-list |
| [Hagezi](https://github.com/hagezi/dns-blocklists) | Pro, Ultimate, and Multi lists |
| [StevenBlack](https://github.com/StevenBlack/hosts) | Unified hosts with extensions |
| [Firebog](https://firebog.net/) | Curated tick lists |
| [NextDNS](https://github.com/nextdns/metadata) | Native tracking domains |
| [Developer Dan](https://www.github.developerdan.com/hosts/) | Ads and tracking extended |
| [Phishing.Database](https://github.com/mitchellkrogza/Phishing.Database) | Active phishing domains |
| [BlocklistProject](https://github.com/blocklistproject/Lists) | Category-specific lists |

---

## ⚡ Features

- **Parallel Processing** — Multi-threaded URL fetching for fast updates
- **Auto-Cleanup** — Broken URLs are automatically removed from seed list
- **Smart Splitting** — Large files split to comply with GitHub limits
- **Category-Based** — Domains organized by type (ads, tracking, malware, etc.)

---

## 🔄 Updates

Lists are regenerated every **30 minutes** with automatic deduplication.

---

## 📜 License

Public domain. Use freely.

---

**Maintainer:** [ErebusTN](https://github.com/EGen-V)  
**Last Update:** January 2026
