# ▣ CloudChef — Cloud Security Log Parser

> A zero-dependency, 100% client-side log analysis console built specifically for AWS CloudTrail, Okta System Logs, and Azure Activity exports. 

[**Live Application Demo**](https://www.shenouda.nl/cloudchef/)

---

## 🚨 The Problem

Every security analyst knows the exact feeling: a SOC alert flags at 23:47 with a message like *"Can you look at this CloudTrail dump?"* and you're forwarded a raw 60MB JSON file. 

* **Editor Lag:** Standard text editors like Notepad freeze or crash entirely trying to open it.
* **Data Leakage Risks:** You **cannot** paste or upload the file into a generic online SaaS web tool—the data is too sensitive and contains corporate identities, private IP spaces, and infrastructure credentials.
* **Tooling Overkill:** Accessing a heavy enterprise SIEM like Splunk or spinning up local database engines for a quick, one-off triage call is complete overkill.

The result? You end up wrestling with complex `jq` scripts in a terminal window until your eyes bleed.

## 🛡️ The Solution: Privacy by Architecture

**CloudChef** is a lightning-fast, standalone single-page web workbench that lets you ingest, parse, and thread large cloud dumps entirely inside your local browser memory space. 

* **100% Client-Side Processing:** Your logs never leave your computer. There is no backend application server, no tracking pixels, no analytics collection, and zero telemetry tracking.
* **Zero Dependencies:** Written purely in vanilla HTML5, CSS3, and modern JavaScript. No frameworks, no third-party node packages, no build steps, and no remote dependencies.
* **Instant Containment:** Because data resides strictly in temporary browser RAM, everything completely vanishes the moment you refresh or close the tab. It is ideal for highly regulated compliance environments and sensitive corporate forensic discovery.

---

## 🚀 Key Features

* **Massive File Capacity:** Fluidly reads logs up to **100MB** (roughly 50,000 to 100,000 JSON lines) without choking.
* **Web Worker Performance Pipeline:** Data parsing, vendor format sniffing, sorting, and indexing loops are shifted out of the main thread and into a background `parser.worker.js` script to keep your browser completely responsive.
* **Automated Provider Sniffing:** Drop a log file in and the engine dynamically detects the schema signature, normalizes the event records, and creates a unified chronological story feed.
* **Interactive Activity Histogram:** Paints a high-performance, lightweight HTML5 canvas timeline mapping log event volume density. Click a specific spike column to instantly zoom and crop the main timeline feed to that precise timestamp window.
* **Lucene-Lite Structured Queries:** Filter thousands of nested rows instantly using targeted token syntax match key-value pairs (e.g., `actor:alice ip:185.220.101.7 action:Delete`).
* **Interactive Deep Inspector Panel:** Click any timeline record to open an elegant, color-coded, nested JSON syntax text view with integrated secure context clipboard tools.
* **One-Click Forensics Export:** Filter an attack sequence down to the matching lines and instantly download a snapshot in clean **JSON (Pretty)**, **NDJSON (Streamable)**, or **CSV (Spreadsheet)** formats for official incident reporting.

---

## 🛠️ Architecture & Log Normalization Matrix

CloudChef evaluates incoming data structures against specific verification keys to index metadata dynamically without standard data stores:

| Cloud Target Profile | Ingestion Signature Key | Normalized Time Property | Normalized Actor Identity |
| :--- | :--- | :--- | :--- |
| **AWS CloudTrail** | `eventSource` \| `userIdentity` | `eventTime` | `userIdentity.userName` \| `.arn` \| `.type` |
| **Okta System Log** | `published` \| `eventType` | `published` | `actor.displayName` \| `actor.alternateId` |
| **Azure Activity** | `operationName` \| `callerIpAddress` | `time` \| `eventTimestamp` | `caller` \| `identity.claims.name` |
| **Generic JSON** | *Automatic Fallback* | `timestamp` \| `time` \| `@timestamp` | `user` \| `actor` \| `username` |

---

## 🔍 Lucene-Lite Query Syntax

Quickly filter out background noise on-the-fly. The custom parsing engine separates field-specific constraints from free text and references a fast, pre-computed search string cache:

* **Field Constraints:** Match specific parameters using `key:value` syntax (e.g., `actor:alice` or `ip:198.51.100.22`).
* **Multi-Token Filtering:** Chain parameters cleanly across arrays (e.g., `action:Delete ip:185.220.101.7`).
* **Quoted Value Boundaries:** Handle structured entries carrying empty space text blocks (e.g., `actor:"Alice Admin"`).
* **Fuzzy Free Text Lookups:** Type any plain word string (e.g., `"console login"` or `Failure`) to execute a global fuzzy cross-reference search scan across the record.

---

## 📦 Getting Started & Local Hosting

Because this layout utilizes standard frontend files, it features zero hosting overhead. The utility runs perfectly directly out of a single flat local folder.

### File Tree Structure
```text
cloudchef/
├── index.html        # Main interface shell layout, metrics nodes, and panels
├── style.css         # Modern, high-visibility dark theme grid and status designs
├── app.js            # Main thread canvas layout painters and filtering listeners
└── parser.worker.js  # Background parsing thread handling resource sorting loops

### Run Options
1. **Local Mode:** Clone or download this repository folder to your machine. Double-click `index.html` to open it locally inside any modern secure web browser. It runs completely offline after initialization.
2. **Static Web Server:** Upload the four folder files onto any file server layer, static corporate edge directory path, **GitHub Pages** distribution root path, Vercel, or Netlify workspace node.

---

## 👨‍💻 Author & License

* Created and engineered with passion by **[Joe Shenouda](https://www.shenouda.nl)**.
* Distributed openly under the **MIT License**. Free to run, adapt, fork, copy, and scale across active security teams, blue team squads, and digital forensics response units globally.
