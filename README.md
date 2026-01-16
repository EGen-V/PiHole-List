# 🛡️ ErebusTN Pi-hole Blocklists

[![Domain Count](https://img.shields.io/badge/domains-6M+-blue)](https://github.com/EGen-V/PiHole-List)
[![Updated](https://img.shields.io/badge/updated-every%2030%20min-green)](https://github.com/EGen-V/PiHole-List)
[![License](https://img.shields.io/badge/license-public%20domain-lightgrey)](https://github.com/EGen-V/PiHole-List)
[![Auto-Update](https://github.com/EGen-V/PiHole-List/actions/workflows/update-blocklist.yml/badge.svg)](https://github.com/EGen-V/PiHole-List/actions)

Curated DNS blocklists for Pi-hole, AdGuard Home, and other DNS-based ad blockers. Automatically updated every 30 minutes with intelligent deduplication and categorization.

---

## 📋 Available Lists

| File | Description | Domains | Size |
|------|-------------|---------|------|
| [`blacklist.txt.part1`](https://raw.githubusercontent.com/EGen-V/PiHole-List/main/blacklist.txt.part1) | **Master list** — All domains combined (Part 1) | 3,820,463 | 90.00 MB |
| [`blacklist.txt.part2`](https://raw.githubusercontent.com/EGen-V/PiHole-List/main/blacklist.txt.part2) | **Master list** — All domains combined (Part 2) | 2,371,340 | 54.96 MB |
| [`categories/spam.txt`](https://raw.githubusercontent.com/EGen-V/PiHole-List/main/categories/spam.txt) | Email spam, referrer spam | 87,706 | 1.45 MB |
| [`categories/suspicious.txt`](https://raw.githubusercontent.com/EGen-V/PiHole-List/main/categories/suspicious.txt) | Heuristically flagged domains | 1,541,973 | 32.89 MB |
| [`categories/advertising.txt`](https://raw.githubusercontent.com/EGen-V/PiHole-List/main/categories/advertising.txt) | Ads, banners, ad networks | 628,694 | 14.67 MB |
| [`categories/tracking.txt`](https://raw.githubusercontent.com/EGen-V/PiHole-List/main/categories/tracking.txt) | Analytics, telemetry, Smart TV trackers | 748,608 | 19.46 MB |
| [`categories/malicious.txt`](https://raw.githubusercontent.com/EGen-V/PiHole-List/main/categories/malicious.txt) | Malware, phishing, scams | 1,672,113 | 38.76 MB |
| [`categories/porn.txt`](https://raw.githubusercontent.com/EGen-V/PiHole-List/main/categories/porn.txt) | Adult content | 2,501,353 | 60.81 MB |
| [`categories/gambling.txt`](https://raw.githubusercontent.com/EGen-V/PiHole-List/main/categories/gambling.txt) | Casinos, betting sites | 194,998 | 3.59 MB |

---

## 🚀 Quick Start

### Pi-hole

1. Go to **Group Management → Adlists**
2. Add the raw URLs:
   ```
   https://raw.githubusercontent.com/EGen-V/PiHole-List/main/blacklist.txt.part1
   https://raw.githubusercontent.com/EGen-V/PiHole-List/main/blacklist.txt.part2
   ```
   
   Or add specific categories:
   ```
   https://raw.githubusercontent.com/EGen-V/PiHole-List/main/categories/advertising.txt
   https://raw.githubusercontent.com/EGen-V/PiHole-List/main/categories/tracking.txt
   https://raw.githubusercontent.com/EGen-V/PiHole-List/main/categories/malicious.txt
   ```

3. Run **Tools → Update Gravity**

### AdGuard Home

1. Go to **Filters → DNS blocklists**
2. Click **Add blocklist → Add a custom list**
3. Add each URL separately (AdGuard Home has a per-list size limit)

### Other DNS Blockers

Most DNS-based blockers support the same URL format. Check your specific software's documentation for adding custom blocklists.

---

## 📊 Sources

These lists aggregate and deduplicate domains from **100+ trusted sources** including:

| Source | Description |
|--------|-------------|
| [OISD](https://oisd.nl/) | Comprehensive mega-list with minimal false positives |
| [Hagezi](https://github.com/hagezi/dns-blocklists) | Pro, Ultimate, and category-specific lists |
| [StevenBlack](https://github.com/StevenBlack/hosts) | Unified hosts with extensions |
| [Firebog](https://firebog.net/) | Curated collection of tick lists |
| [NextDNS](https://github.com/nextdns/metadata) | Native tracking protection |
| [Developer Dan](https://www.github.developerdan.com/hosts/) | Ads and tracking extended |
| [Phishing.Database](https://github.com/mitchellkrogza/Phishing.Database) | Active phishing domains |
| [BlocklistProject](https://github.com/blocklistproject/Lists) | Category-specific blocklists |
| [1Hosts](https://github.com/badmojr/1Hosts) | Pro and Lite variants |
| [NoTracking](https://github.com/notracking/hosts-blocklists) | Privacy-focused lists |

*Full source list available in `list.txt`*

---

## ⚡ Features

### Intelligent Processing
- **Multi-format Support** — Automatically detects and parses hosts files, domain lists, and AdBlock rules
- **Smart Categorization** — Domains automatically categorized by type (ads, tracking, malware, etc.)
- **Deduplication** — Removes duplicates across all sources
- **Whitelist Support** — Exclude domains and entire TLDs from blocking

### Performance Optimized
- **Parallel Processing** — Multi-threaded URL fetching for 10x faster updates
- **Memory Efficient** — Handles millions of domains without excessive RAM usage
- **Smart Splitting** — Large files automatically split to comply with GitHub's 100MB limit
- **Change Detection** — Only commits when actual changes occur

### Reliability & Monitoring
- **Health Tracking** — Monitors source reliability and automatically removes persistently broken URLs
- **Automatic Backups** — Keeps last 10 versions before each update
- **Error Recovery** — Gracefully handles network failures and malformed data
- **Progress Tracking** — Real-time progress bars and detailed logging

### Automation
- **GitHub Actions** — Fully automated updates every 30 minutes
- **README Auto-Update** — Statistics table updates automatically
- **Git Integration** — Smart commits with detailed change summaries

---

## 🔄 Update Frequency

- **Automatic**: Every 30 minutes via GitHub Actions
- **On-Demand**: Manual trigger available in GitHub Actions tab
- **Change-Driven**: Also updates when source list (`list.txt`) changes

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Add Sources**: Submit PRs with new blocklist URLs
2. **Report Issues**: Found false positives? Open an issue
3. **Improve Code**: Performance optimizations, bug fixes, new features

### Suggesting New Sources

Open an issue with:
- Source URL
- Description
- Estimated domain count
- Update frequency
- License/terms

---

## 📜 License

Public domain. Use freely. No attribution required (but appreciated!).

Individual blocklist sources may have their own licenses. Respect upstream source terms.

---

## ⚠️ Disclaimer

These blocklists are provided "as-is" without warranty. While we strive for accuracy:

- **False positives may occur** — Some legitimate sites might be blocked
- **Test before deploying** — Use in a test environment first
- **Maintain whitelists** — Keep a whitelist for critical services
- **Not legal advice** — Blocking decisions are your responsibility

---

## 🙏 Acknowledgments

Thanks to all the providers of the upstream blocklists that make this project possible:

- [OISD](https://oisd.nl/) by sjhgvr
- [Hagezi](https://github.com/hagezi/dns-blocklists) by Hagezi
- [StevenBlack](https://github.com/StevenBlack/hosts) by Steven Black
- [Firebog](https://firebog.net/) by WaLLy3K
- And 100+ other contributors

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/EGen-V/PiHole-List/issues)
- **Discussions**: [GitHub Discussions](https://github.com/EGen-V/PiHole-List/discussions)

---

**Maintainer:** [ErebusTN](https://github.com/EGen-V)

**Last Update:** January 2026

**Repository:** [github.com/EGen-V/PiHole-List](https://github.com/EGen-V/PiHole-List)