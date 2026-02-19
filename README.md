# phishing-detector# 🛡️ AI Phishing Detector

> **Detect phishing links, email spoofing, and scam messages instantly using AI-powered heuristic analysis — 100% client-side, private, no data ever leaves your device.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![HTML](https://img.shields.io/badge/Built%20With-HTML%2FCSS%2FJS-orange.svg)](.)
[![No Backend](https://img.shields.io/badge/Backend-None-green.svg)](.)
[![Privacy](https://img.shields.io/badge/Privacy-100%25%20Local-purple.svg)](.)

---

## ✨ Features

- 🔗 **URL / Link Analyzer** — Detects phishing links, spoofed domains, suspicious TLDs, redirect chains, and obfuscated URLs
- 📧 **Email Analyzer** — Identifies sender spoofing, domain mismatches, urgency tactics, credential harvesting, and malicious embedded links
- 💬 **Message / SMS Analyzer** — Catches lottery scams, OTP phishing, brand impersonation, and shortened URL traps
- 📊 **Risk Score 0–100** — Each analysis returns a precise score with a visual animated gauge
- 🔍 **Signal Breakdown** — Every triggered detection signal is explained in plain English
- 📁 **Scan History** — Last 5 scans saved locally in your browser (localStorage)
- 🔒 **100% Private** — Runs entirely in your browser, zero network requests, zero telemetry

---

## 🚀 Getting Started

No installation, no dependencies, no build step required.

```bash
git clone https://github.com/YOUR_USERNAME/phishing-detector.git
cd phishing-detector
```

Then simply open `index.html` in any modern browser:

- **Windows:** Double-click `index.html`  
- **macOS / Linux:** `open index.html` or `xdg-open index.html`

---

## 🎯 Risk Levels

| Score | Level | Indicator |
|-------|-------|-----------|
| 0 – 25 | ✅ Safe | No significant phishing indicators |
| 26 – 55 | ⚠️ Suspicious | Some warning signs detected |
| 56 – 79 | 🚨 Likely Phishing | Strong phishing indicators |
| 80 – 100 | ☠️ Phishing | High-confidence phishing detected |

---

## 🔬 Detection Signals

### 🔗 URL Analysis (15+ signals)
| Signal | Description |
|--------|-------------|
| Suspicious TLD | `.tk`, `.xyz`, `.ml`, `.cf`, `.top`, `.click` and 20+ more |
| Brand Spoofing | `paypa1`, `g00gle`, `amaz0n`, `micros0ft`, `appl3` etc. |
| IP-based URL | Direct IP address instead of domain name |
| HTTP Protocol | Unencrypted connection (no HTTPS) |
| Excessive Subdomains | 4+ subdomain levels used to bury brand |
| Redirect Chains | `/redirect?url=`, `/go?link=`, `returnurl=` etc. |
| Phishing Keywords | `login`, `verify`, `update-account`, `credential` in path |
| URL Obfuscation | `@` in URL, hex encoding, double slashes |
| Shortened URLs | bit.ly, tinyurl, t.co, ow.ly and 15+ more |
| Homograph Attack | Unicode/lookalike characters in domain |
| Excessive Length | URLs over 75–100 characters |
| Data URIs | `data:` scheme used to bypass filters |

### 📧 Email Analysis (9+ signals)
| Signal | Description |
|--------|-------------|
| Sender Spoofing | Free email (Gmail/Yahoo) impersonating brand |
| Domain Mismatch | Sender domain ≠ mentioned brand domain |
| Urgency Language | 30+ patterns: "act now", "account suspended", "verify immediately" |
| Credential Request | Asks for password, card number, PIN, OTP |
| Malicious Links | Embedded URLs analyzed with the URL engine |
| Dangerous Attachments | `.exe`, `.docm`, `.bat`, `.zip` mentioned |
| Grammar Red Flags | "Dear valued customer", "kindly click", "do the needful" |
| ALL CAPS Subject | Scare tactic to create urgency |
| Reply-To Mismatch | Custom Reply-To header to divert responses |

### 💬 Message / SMS Analysis (7+ signals)
| Signal | Description |
|--------|-------------|
| Scam Patterns | 25+ regex patterns for lottery, prize, OTP fraud |
| Impersonation | Banks, IRS, FedEx, government agency spoofing |
| Urgency Tactics | "Act now", "expires today", "respond immediately" |
| Shortened URLs | Hides real link destination |
| Monetary Lure | Dollar/rupee amounts used as bait |
| Personal Data Request | Aadhar, PAN, OTP, CVV, account number |
| Vishing Pattern | Urgently asks to call a phone number |

---

## 🧪 Test It Yourself

### Phishing URL (should score ~90/100)
```
http://paypa1.com.verify-account.tk/login?password=reset&token=abc123
```

### Phishing Email
```
From: PayPal Support <security-alert@gmail.com>
Subject: URGENT: Your account has been suspended
Body: Dear valued customer, your PayPal account has been limited. 
      Please verify immediately: http://paypa1-secure.tk/login
      Failure to verify will result in permanent suspension.
      Enter your password and card details below.
```

### Scam SMS
```
Congratulations! You have WON $5,000! 
Claim your prize now before it expires: bit.ly/claim-prize
Act now! Call toll-free immediately. Reply your OTP to confirm.
```

### Safe URL (should score 0/100)
```
https://google.com
```

---

## 📁 Project Structure

```
phishing-detector/
├── index.html      # Main application shell (tabs, results, history, tips)
├── styles.css      # Dark glassmorphism UI design system
├── detector.js     # AI detection engine (patterns, scoring, signal library)
├── app.js          # UI orchestration (tabs, forms, gauge, history)
├── README.md       # This file
└── LICENSE         # MIT License
```

---

## 🏗️ Architecture

The project is intentionally zero-dependency and zero-build. The detection pipeline works as follows:

```
User Input
    │
    ▼
┌─────────────────────────────────────────────────────┐
│                  detector.js                        │
│                                                     │
│  analyzeURL(url)   analyzeEmail({sender,subj,body}) │
│  analyzeMessage(text)                               │
│                                                     │
│  Each function runs input through:                  │
│  1. Pattern matching (regex + string patterns)      │
│  2. Weighted signal scoring (0–25 pts per signal)   │
│  3. Score clamped to 0–100                          │
│  4. Risk level classification                       │
│  5. Returns { score, level, signals[] }             │
└─────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────┐
│                    app.js                           │
│  Renders: SVG gauge, risk badge, signal breakdown   │
│  Saves to localStorage history                      │
└─────────────────────────────────────────────────────┘
```

---

## ⚠️ Disclaimer

This tool uses **heuristic analysis** and pattern matching. It is designed to assist users in identifying common phishing tactics and is **not a replacement** for professional cybersecurity software. Results may include:

- **False positives** — legitimate URLs flagged due to keyword or TLD matches
- **False negatives** — sophisticated phishing not caught by current patterns

Always cross-reference with additional tools like [Google Safe Browsing](https://transparencyreport.google.com/safe-browsing/search) for critical decisions.

---

## 📜 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

Contributions are welcome! To improve detection:

1. Fork the repository
2. Add new signals to `detector.js` in the appropriate section
3. Test with real phishing samples from [PhishTank](https://www.phishtank.com/)
4. Submit a pull request

---

## 🙏 Acknowledgements

- Pattern libraries inspired by common phishing indicators documented by [APWG](https://apwg.org/), [PhishTank](https://www.phishtank.com/), and [OWASP](https://owasp.org/)
- UI design inspired by modern dark-mode dashboard trends
