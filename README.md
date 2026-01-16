# 🛡️ ErebusTN Pi-hole Blocklists

Curated DNS blocklists for Pi-hole, AdGuard Home, and other DNS-based ad blockers.

---

## 📋 Available Lists

| File | Description | Domains | Size |
|------|-------------|---------|------|
| [`blacklist.txt.part1`](blacklist.txt.part1) | **Master list** — All domains combined (Part 1) | 3,820,804 | 90.00 MB |
| [`blacklist.txt.part2`](blacklist.txt.part2) | **Master list** — All domains combined (Part 2) | 2,373,327 | 55.02 MB |
| [`categories/spam.txt`](categories/spam.txt) | Email spam, referrer spam | 87,709 | 1.45 MB |
| [`categories/suspicious.txt`](categories/suspicious.txt) | Heuristically flagged domains | 1,536,633 | 32.79 MB |
| [`categories/advertising.txt`](categories/advertising.txt) | Ads, banners, ad networks | 629,151 | 14.68 MB |
| [`categories/tracking.txt`](categories/tracking.txt) | Analytics, telemetry, Smart TV trackers | 749,243 | 19.49 MB |
| [`categories/malicious.txt`](categories/malicious.txt) | Malware, phishing, scams | 1,671,934 | 38.76 MB |
| [`categories/porn.txt`](categories/porn.txt) | Adult content | 2,501,095 | 60.80 MB |
| [`categories/gambling.txt`](categories/gambling.txt) | Casinos, betting sites | 194,988 | 3.60 MB |

---

## 🚀 Quick Start

### Pi-hole

1. Go to **Group Management → Adlists**
2. Add the raw URL:
   ```
   https://raw.githubusercontent.com/EGen-V/PiHole-List-Creator/main/blacklist.txt
   ```
   > **Note:** If `blacklist.txt` is missing, it has been split into parts due to size limits (e.g., `blacklist.txt.part1`, `blacklist.txt.part2`). Add each part URL separately.

3. Run **Tools → Update Gravity**

### AdGuard Home

1. Go to **Filters → DNS blocklists**
2. Click **Add blocklist → Add a custom list**
3. Paste the raw URL above (or all part URLs if split)

---

## 📊 Sources

These lists aggregate and deduplicate domains from 100+ trusted sources including:

- **OISD** — Comprehensive mega-list
- **Hagezi** — Pro and Ultimate lists
- **StevenBlack** — Unified hosts
- **Firebog** — Curated tick lists
- **NextDNS** — Native tracking domains
- **Developer Dan** — Ads and tracking extended
- **Phishing.Database** — Active phishing domains
- **BlocklistProject** — Category-specific lists

---

## 🔄 Updates

Lists are regenerated every **30 minutes** with automatic deduplication.

---

## 📜 License

Public domain. Use freely.

---

**Maintainer:** [ErebusTN](https://github.com/ErebusTN)  
**Last Update:** January 2026
