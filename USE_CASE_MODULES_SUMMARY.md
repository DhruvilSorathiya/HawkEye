## SUMMARY STATISTICS

| Use Case | Module Count | Purpose |
|----------|--------------|---------|
| **Footprint** | 144 modules | Initial reconnaissance and attack surface mapping |
| **Investigate** | 187 modules | Threat intelligence and malicious activity detection |
| **Passive** | 183 modules | Covert intelligence gathering without target contact |
| **All** | 234 modules | Comprehensive investigation (all modules enabled) |

---

## 🔍 FOOTPRINT (144 Modules)

**Purpose:** Understand what information the target exposes to the Internet. Gain understanding about network perimeter, associated identities, and other information through web crawling and search engines.

**When to use:** Initial reconnaissance, attack surface mapping, external exposure assessment

### Key Module Categories:

#### DNS & Network Discovery (20+ modules)
- DNS Resolver, DNS Brute-forcer, DNS Zone Transfer
- BGPView, ARIN, RIPE
- Port Scanner - TCP
- Robtex, ViewDNS.info

#### Search Engines (10+ modules)
- Google, Bing, DuckDuckGo
- SHODAN, CommonCrawl
- grep.app, searchcode

#### Cloud Storage Discovery (5 modules)
- Amazon S3 Bucket Finder
- Azure Blob Finder
- Google Object Storage Finder
- Digital Ocean Space Finder
- Grayhat Warfare

#### Social Media & Accounts (15+ modules)
- Account Finder (500+ platforms)
- Social Media Profile Finder
- Social Links, Social Network Identifier
- Twitter, Flickr, MySpace, Venmo
- Keybase, Gravatar

#### Email Intelligence (10+ modules)
- E-Mail Address Extractor
- EmailCrawlr, EmailFormat, EmailRep
- Hunter.io, Snov
- HaveIBeenPwned (breach checking)

#### Web Intelligence (15+ modules)
- Web Spider, Page Information
- BuiltWith (technology detection)
- Web Analytics Extractor
- SSL Certificate Analyzer
- Web Server Identifier, Web Framework Identifier
- WhatCMS

#### Business Intelligence (10+ modules)
- Company Name Extractor
- OpenCorporates, GLEIF
- Clearbit, FullContact
- NeutrinoAPI

#### Dark Web (5 modules)
- Ahmia (Tor search)
- TORCH
- Onion.link
- Onionsearchengine.com
- Wikileaks

#### Cryptocurrency (5 modules)
- Bitcoin Finder, Blockchain
- Ethereum Address Extractor, Etherscan

#### Geographic & Contact (8 modules)
- Country Name Extractor
- Google Maps, OpenStreetMap
- CallerName, Phone Number Extractor
- Twilio, numverify

#### Code & Development (8 modules)
- Github
- PasteBin, Psbdmp
- Cross-Referencer
- Archive.org (Wayback Machine)

#### Data Extraction (10+ modules)
- Base64 Decoder, Binary String Extractor
- Cookie Extractor, Hash Extractor
- Credit Card Number Extractor, IBAN Number Extractor
- Error String Extractor
- File Metadata Extractor

#### Security Tools (8 modules)
- Tool - Nmap
- Tool - CMSeeK
- Tool - DNSTwist
- Tool - testssl.sh
- Tool - TruffleHog
- Tool - WAFW00F
- Tool - WhatWeb

### Sample Modules:
1. DNS Resolver - Resolves domains to IP addresses
2. SHODAN - Internet-connected device information
3. Account Finder - Search 500+ social platforms
4. Amazon S3 Bucket Finder - Discover exposed cloud storage
5. BuiltWith - Identify web technologies
6. HaveIBeenPwned - Check for data breaches
7. Github - Search code repositories
8. Ahmia - Dark web search engine
9. Google Maps - Geographic information
10. Port Scanner - TCP - Discover open ports

---

## 🔎 INVESTIGATE (187 Modules)

**Purpose:** Best for when you suspect the target to be malicious but need more information. Performs basic footprinting plus queries blacklists and threat intelligence sources.

**When to use:** Threat investigation, malicious activity analysis, security incident response

### Key Module Categories:

#### Threat Intelligence (50+ modules)
- abuse.ch, AbuseIPDB, AlienVault OTX
- VirusTotal, Hybrid Analysis
- ThreatCrowd, ThreatMiner, ThreatFox
- Maltiverse, MalwarePatrol
- Pulsedive, MetaDefender
- Koodous (Android malware)
- VXVault.net

#### Blacklist Checking (30+ modules)
- Spamhaus Zen, SpamCop, SORBS
- blocklist.de, botvrij.eu
- DroneBL, UCEPROTECT
- BotScout, CleanTalk Spam List
- Greensnow, CINS Army List
- multiproxy.org Open Proxies
- TOR Exit Nodes

#### Reputation Services (20+ modules)
- AlienVault IP Reputation
- EmailRep, Fraudguard
- spur.us, Project Honey Pot
- Internet Storm Center
- FortiGuard Antispam
- VoIP Blacklist (VoIPBL)

#### DNS Security (15+ modules)
- AdBlock Check, AdGuard DNS
- CleanBrowsing.org, DNS for Family
- CloudFlare DNS, Comodo Secure DNS
- OpenDNS, Quad9, Yandex DNS
- CoinBlocker Lists

#### Phishing & Fraud (8 modules)
- PhishTank, PhishStats
- OpenPhish
- Fraudguard
- Open Bug Bounty

#### Breach Intelligence (10+ modules)
- HaveIBeenPwned
- Dehashed, IntelligenceX
- LeakIX, Leak-Lookup
- Trashpanda
- Iknowwhatyoudownload.com

#### Malware Analysis (8 modules)
- Hybrid Analysis
- VirusTotal
- Koodous
- MetaDefender
- VXVault.net
- MalwarePatrol

#### Threat Feeds (10+ modules)
- Custom Threat Feed
- Emerging Threats
- CyberCrime-Tracker.net
- Talos Intelligence
- Threat Jammer
- Focsec
- Steven Black Hosts

#### Certificate Intelligence (5 modules)
- CertSpotter
- Certificate Transparency (crt.sh)
- SSL Certificate Analyzer
- CIRCL.LU

#### Cryptocurrency Abuse (3 modules)
- Bitcoin Who's Who
- Bitcoin Finder
- Blockchain

#### Security Scanning (10+ modules)
- Port Scanner - TCP
- Tool - Nmap
- Tool - CMSeeK
- Tool - testssl.sh
- Tool - WAFW00F
- Tool - WhatWeb
- Subdomain Takeover Checker

#### Defacement Monitoring (2 modules)
- Zone-H Defacement Check
- CyberCrime-Tracker.net

### All Footprint Modules PLUS:
- All 144 Footprint modules
- Plus 43 additional threat intelligence modules
- Total: 187 modules

### Sample Modules:
1. VirusTotal - Multi-engine malware scanner
2. AbuseIPDB - IP reputation database
3. Spamhaus Zen - Email/IP blacklist
4. PhishTank - Phishing URL database
5. Hybrid Analysis - Malware sandbox
6. ThreatCrowd - Threat intelligence aggregator
7. AlienVault OTX - Open Threat Exchange
8. Dehashed - Breach database
9. OpenPhish - Phishing feed
10. Zone-H - Defacement archive

---

## 🕵️ PASSIVE (183 Modules)

**Purpose:** When you don't want the target to suspect they are being investigated. Gathers information without touching the target or their affiliates.

**When to use:** Covert intelligence gathering, no direct target contact, stealth reconnaissance

### Key Characteristics:
- **No Direct Contact:** Modules don't connect to target infrastructure
- **Third-Party Sources:** Only queries external databases and services
- **Stealth Mode:** Target won't see any scanning activity
- **Historical Data:** Uses archived and cached information

### Key Module Categories:

#### Passive DNS (15+ modules)
- DNS Resolver (passive mode)
- DNSGrep, DNS Raw Records
- Mnemonic PassiveDNS
- F-Secure Riddler.io
- CIRCL.LU
- Crobat API

#### Search Engines (10+ modules)
- Google, Bing, DuckDuckGo
- SHODAN (API only, no direct scan)
- Censys (API only)
- BinaryEdge (API only)

#### Threat Intelligence (50+ modules)
- All threat intelligence sources
- Blacklist databases
- Reputation services
- Malware databases
- (All query-only, no active scanning)

#### Public Records (20+ modules)
- WHOIS databases
- Certificate Transparency logs
- BGP/ASN databases
- ARIN, RIPE registries
- OpenCorporates

#### Breach Databases (10+ modules)
- HaveIBeenPwned
- Dehashed, IntelligenceX
- LeakIX
- PasteBin, Psbdmp

#### Social Media (15+ modules)
- Account Finder (passive lookup)
- Social Media Profile Finder
- Social Links
- Twitter, Flickr, MySpace
- Gravatar, Keybase

#### Web Archives (5 modules)
- Archive.org (Wayback Machine)
- CommonCrawl
- Google cache (via search)

#### Cloud Storage (5 modules)
- Amazon S3 Bucket Finder (name guessing)
- Azure Blob Finder
- Google Object Storage Finder
- Digital Ocean Space Finder
- Grayhat Warfare (database)

#### Email Intelligence (10+ modules)
- EmailRep, EmailFormat
- EmailCrawlr, Hunter.io
- Snov, Debounce
- Trumail

#### Code Repositories (5 modules)
- Github (API search)
- grep.app
- searchcode
- PasteBin, Psbdmp

#### Business Intelligence (10+ modules)
- OpenCorporates, GLEIF
- Clearbit, FullContact
- NeutrinoAPI, NameAPI

#### Cryptocurrency (5 modules)
- Bitcoin Finder
- Bitcoin Who's Who
- Blockchain.com API
- Ethereum, Etherscan

#### Geographic (5 modules)
- Country Name Extractor
- ipapi.co, ipapi.com
- IPInfo.io, ipstack
- OpenStreetMap

### Modules EXCLUDED from Passive:
- **DNS Brute-forcer** - Actively queries target DNS
- **DNS Zone Transfer** - Directly contacts target DNS
- **Port Scanner** - Directly scans target
- **Web Spider** - Crawls target website
- **Tool - Nmap** - Active network scanning
- **DNS Common SRV** - Queries target DNS
- **DNS Look-aside** - Queries target DNS

### Sample Modules:
1. SHODAN API - Query existing scan data (no new scan)
2. Certificate Transparency - Public certificate logs
3. Archive.org - Historical website snapshots
4. HaveIBeenPwned - Breach database lookup
5. WHOIS - Public registration data
6. BGPView - BGP routing information
7. Github API - Code search (no target contact)
8. Mnemonic PassiveDNS - Historical DNS data
9. OpenCorporates - Business registry
10. CommonCrawl - Web archive search

---

## 🔄 MODULE OVERLAP ANALYSIS

### Modules in ALL Three Use Cases (Common Core - 120+ modules)
These modules are versatile and work in all scenarios:
- DNS Resolver
- WHOIS
- SHODAN
- BGPView
- Most threat intelligence sources
- Email extractors
- Social media finders
- Cryptocurrency lookups
- Geographic lookups

### Footprint-Only Modules (24 modules)
Active reconnaissance modules:
- DNS Brute-forcer
- DNS Zone Transfer
- DNS Common SRV
- DNS Look-aside
- Port Scanner - TCP
- Web Spider
- Tool - Nmap
- Tool - NBTScan
- Tool - Onesixtyone
- Junk File Finder
- Interesting File Finder
- Similar Domain Finder
- TLD Searcher
- Subdomain Takeover Checker

### Investigate-Only Modules (4 modules)
Specialized threat modules:
- Custom Threat Feed
- Emerging Threats
- Some specialized blacklists

### Passive-Only Modules (0 modules)
All passive modules are shared with other use cases

---

## 💡 QUICK ANSWERS FOR FACULTY

### Q: How many modules in each use case?
**A:** 
- Footprint: 144 modules
- Investigate: 187 modules  
- Passive: 183 modules
- All: 234 modules (total unique modules)

### Q: What's the difference between them?
**A:**
- **Footprint** = Active reconnaissance (touches target)
- **Investigate** = Footprint + Threat intelligence
- **Passive** = No target contact (third-party sources only)

### Q: Which modules are in Footprint but not Passive?
**A:** Active scanning modules like:
- DNS Brute-forcer, DNS Zone Transfer
- Port Scanner, Nmap
- Web Spider
- DNS Common SRV, DNS Look-aside

### Q: Which modules are in Investigate but not Footprint?
**A:** Threat intelligence modules like:
- VirusTotal, AbuseIPDB
- Spamhaus, PhishTank
- AlienVault OTX
- Hybrid Analysis
- Zone-H Defacement Check

### Q: Can you give examples from each category?
**A:** Yes! See the "Sample Modules" section under each use case above.

### Q: How does the system decide which modules to run?
**A:** 
1. User selects use case (Footprint/Investigate/Passive/All)
2. System filters modules by their `useCases` metadata
3. Modules are further filtered by target type compatibility
4. Selected modules run in parallel (3 concurrent by default)

---

## 📋 PRESENTATION TIPS

### When Explaining to Faculty:

1. **Start with the numbers:**
   - "We have 234 total intelligence modules"
   - "Organized into 4 use cases based on scanning approach"

2. **Explain the use cases:**
   - "Footprint for reconnaissance - 144 modules"
   - "Investigate for threat analysis - 187 modules"
   - "Passive for stealth gathering - 183 modules"
   - "All for comprehensive scans - all 234 modules"

3. **Give concrete examples:**
   - "For Footprint: DNS Resolver finds IP addresses"
   - "For Investigate: VirusTotal checks for malware"
   - "For Passive: Archive.org shows historical data"

4. **Highlight the intelligence:**
   - "Each module connects to a different intelligence source"
   - "Sources include: Search engines, threat databases, social media, dark web, etc."
   - "Modules chain together - one module's output feeds into others"

5. **Emphasize automation:**
   - "Manual OSINT would take days or weeks"
   - "HawkEye3 automates all 234 sources"
   - "Runs in parallel for speed"
   - "Results correlated automatically"

---

## 🎯 KEY TAKEAWAYS

1. **234 Total Modules** - Each integrates with a different intelligence source
2. **4 Use Cases** - Organized by scanning approach and purpose
3. **Intelligent Selection** - System automatically picks appropriate modules
4. **Event Chaining** - Modules feed data to each other automatically
5. **Parallel Execution** - 3 modules run concurrently for speed
6. **Comprehensive Coverage** - DNS, web, social media, threat intel, dark web, etc.

---

