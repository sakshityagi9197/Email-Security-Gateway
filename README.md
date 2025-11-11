# Email Security Gateway

> An enterprise-grade email security platform that provides multi-layered threat detection, policy-based routing, and comprehensive analysis of email-based attacks.

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/) [![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688.svg)](https://fastapi.tiangolo.com/) [![React](https://img.shields.io/badge/React-19.1%2B-61DAFB.svg)](https://reactjs.org/) [![Uvicorn](https://img.shields.io/badge/Uvicorn-ASGI-green.svg)](https://www.uvicorn.org/) [![ClamAV](https://img.shields.io/badge/ClamAV-Antivirus-red.svg)](https://www.clamav.net/) [![YARA](https://img.shields.io/badge/YARA-Pattern%20Matching-orange.svg)](https://virustotal.github.io/yara/)

---

## 📋 Table of Contents

| # | Section |
|---|---------|
| 1 | [Overview](#overview) |
| 2 | [The Problem It Solves](#the-problem-it-solves) |
| 3 | [What Makes It Different](#what-makes-it-different) |
| 4 | [Key Features](#key-features) |
| 5 | [Architecture](#architecture) |
| 6 | [Installation](#installation) |
| 7 | [Screenshots](#screenshots) |
| 8 | [Security Features](#security-features) |
| 9 | [API Reference](#api-reference) |
| 10 | [Contributing](#contributing) |
| 11 | [Roadmap](#roadmap) |

---

## 🎯 Overview

**Email Security Gateway** is a sophisticated email security solution designed to protect organizations from the ever-evolving landscape of email-based threats. Built with Python and FastAPI on the backend and React on the frontend, this system acts as an intelligent intermediary that inspects, analyzes, and routes emails based on comprehensive security policies and real-time threat intelligence.

The platform combines multiple industry-standard authentication protocols (DKIM, SPF, DMARC) with advanced threat detection engines (ClamAV, YARA, VirusTotal) to create a robust defense-in-depth security strategy.

---

## 🚨 The Problem It Solves

**Email remains the #1 attack vector for cybercriminals**, with:
- 94% of malware delivered via email
- $1.8 billion lost annually to Business Email Compromise (BEC) attacks
- Phishing attacks increasing by 65% year-over-year

### Challenges in Modern Email Security:

1. **Complex Threat Landscape**: Traditional email filters struggle with sophisticated phishing, spear-phishing, and polymorphic malware that constantly evolves to evade detection.

2. **False Positives**: Overly aggressive filtering blocks legitimate emails, disrupting business operations and causing productivity loss.

3. **Lack of Visibility**: IT teams often lack comprehensive dashboards to monitor email threats, analyze trends, and respond to incidents quickly.

4. **Policy Management**: Organizations need granular control over email policies (blocking attachments, quarantining suspicious domains) but existing solutions are inflexible or expensive.

5. **Integration Challenges**: Most commercial solutions are proprietary, expensive, and difficult to integrate with existing infrastructure.

### How This Solution Addresses These Challenges:

This Email Security Gateway provides:
- **Multi-Engine Detection**: Combines multiple scanning engines (antivirus, YARA rules, VirusTotal reputation) to catch threats that single-engine solutions miss
- **Intelligent Scoring**: Uses heuristic-based threat scoring to minimize false positives while maintaining high detection rates
- **Real-Time Dashboard**: Provides administrators with immediate visibility into email traffic, threats blocked, and quarantine status
- **Flexible Policy Engine**: YAML-based policy configuration allows organizations to define custom rules based on their specific security requirements
- **Cost-Effective**: Open-source foundation with optional integration of commercial APIs (VirusTotal, Hybrid-Analysis) based on budget

---

## 🔥 What Makes It Different

- **Multi-Layer Defense**: Complete security pipeline from authentication (SPF/DKIM/DMARC) to threat detection to policy-based routing
- **Developer-Friendly**: RESTful API, modular architecture, and policy-as-code approach for easy customization
- **Real-Time Intelligence**: WebSocket notifications and interactive dashboards with live threat updates
- **Production-Ready**: JWT authentication, CSRF protection, comprehensive audit logging, and secure password handling

---

## ✨ Key Features

- **Email Authentication**: DKIM, SPF, DMARC verification with domain phishing detection
- **Advanced Threat Detection**: Multi-engine scanning (ClamAV, YARA, VirusTotal) with URL reputation analysis
- **Policy Engine**: YAML-based configuration with rule-based routing and versioning support
- **Real-Time Dashboard**: Interactive analytics, threat visualization, and quarantine management
- **RESTful API**: Complete programmatic access with comprehensive documentation
- **SMTP Integration**: Direct email ingestion with downstream MTA forwarding


## 🏗️ Architecture

### System Flow Diagram
```
┌────────────────────────────────────────────────────────────────┐
│                      Incoming Email                            │
│                   (SMTP / File Upload)                         │
└──────────────────────────┬─────────────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────────────┐
│                    INGESTION LAYER                             │
│   ┌─────────────┐           ┌──────────────────────┐           │
│   │ SMTP Server │           │ File Upload Handler  │           │
│   │ (aiosmtpd)  │           │ (FastAPI endpoint)   │           │
│   └─────────────┘           └──────────────────────┘           │
└──────────────────────────┬─────────────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────────────┐
│                    PARSING LAYER                               │
│   • Extract headers, body, attachments                         │
│   • Decode MIME parts                                          │
│   • Generate structured JSON representation                    │
└──────────────────────────┬─────────────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────────────┐
│                 AUTHENTICATION LAYER                           │
│   ┌──────────┐  ┌──────────┐  ┌────────────────┐               │
│   │SPF Check │  │DKIM Check│  │DMARC Validation│               │
│   └──────────┘  └──────────┘  └────────────────┘               │
│   • Domain reputation analysis                                 │
│   • Phishing detection (homoglyphs, typosquatting)             │
└──────────────────────────┬─────────────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────────────┐
│                THREAT DETECTION LAYER                          │
│   ┌────────┐  ┌────────┐  ┌──────────┐  ┌────────┐             │
│   │ ClamAV │  │  YARA  │  │VirusTotal│  │URL Chk │             │
│   │Scanner │  │ Rules  │  │   API    │  │        │             │
│   └────────┘  └────────┘  └──────────┘  └────────┘             │
│   • Hash computation (MD5, SHA256)                             │
│   • Attachment type validation                                 │
│   • Heuristic threat scoring (0-100)                           │
└──────────────────────────┬─────────────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────────────┐
│                    POLICY ENGINE                               │
│   • Evaluate custom YAML-based rules                           │
│   • Apply organizational policies                              │
│   • Make routing decisions                                     │
└──────────────────────────┬─────────────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────────────┐
│                    ROUTING LAYER                               │
│   ┌────────┐    ┌──────────┐    ┌──────────────────┐           │
│   │ BLOCK  │    │QUARANTINE│    │PASS (Forward MTA)│           │
│   └────────┘    └──────────┘    └──────────────────┘           │
└──────────────────────────┬─────────────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────────────┐
│                 STORAGE & REPORTING                            │
│   • Analysis results (JSON files)                              │
│   • Email archives (quarantine/blocked/recovered)              │
│   • Audit logs                                                 │
│   • Dashboard metrics and charts                               │
└────────────────────────────────────────────────────────────────┘
```

### Component Breakdown

#### Backend Components
```
backend/
├── api/                    # REST API layer
│   ├── server.py          # FastAPI app, middleware, routes
│   ├── auth.py            # JWT authentication
│   ├── dashboard.py       # Metrics and charts
│   ├── emails.py          # Email listing and details
│   ├── policies.py        # Policy management
│   └── storage.py         # File-based data persistence
│
├── ingestion/             # Email intake
│   ├── smtp_server.py     # Async SMTP listener
│   └── ingestion.py       # Email loader
│
├── parser/                # Email parsing
│   └── parser.py          # MIME parsing, attachment extraction
│
├── validation_layer/      # Authentication
│   ├── spf.py            # SPF verification
│   ├── dkim.py           # DKIM signature checking
│   ├── dmarc.py          # DMARC policy validation
│   └── domain_checking.py # Phishing detection
│
├── threat_detection/      # Security scanning
│   ├── analyzer.py        # Main threat analysis orchestrator
│   ├── clamav_scanner.py  # Antivirus integration
│   ├── yara_scanner.py    # YARA rule matching
│   ├── virustotal_api.py  # VirusTotal API client
│   ├── url_checker.py     # URL reputation
│   └── sandbox.py         # Sandbox submission (future)
│
├── policy_attachment/     # Policy engine
│   └── Policy_Engine.py   # YAML-based rule evaluation
│
├── routing/               # Email routing
│   └── email_routing.py   # Route to block/quarantine/pass
│
└── utils/                 # Utilities
    ├── audit_logger.py    # Security event logging
    ├── path_validator.py  # Path traversal protection
    └── errors.py          # Custom exceptions
```

---

## 🚀 Installation

For detailed installation instructions, prerequisites, configuration, and troubleshooting, see **[SETUP.md](SETUP.md)**.

---

## 📸 Screenshots

### Dashboard
Comprehensive metrics showing email volume, threat distribution, and routing decisions.

### Email Detail View
Deep dive into individual emails with full headers, threat scores, and analysis results.

### Policy Management
Create and manage custom security policies with YAML-based configuration.

### Quarantine Management
Review, release, or delete quarantined emails with a single click.

---

## 🔒 Security Features

### Authentication & Authorization
- **JWT-based authentication** with access and refresh tokens
- **Role-based access control** (viewer, analyst, admin)
- **Secure password hashing** using bcrypt
- **Token blacklisting** for logout functionality

### Request Security
- **CSRF protection** on all state-changing endpoints
- **Input validation** using Pydantic models
- **Path traversal protection** for file operations
- **Rate limiting** (configurable)

### Audit & Compliance
- **Comprehensive audit logging** of all security events
- **Detailed analysis records** stored as JSON
- **Email archival** for forensic investigation
- **Configurable retention policies**

### Production Hardening Checklist
Before deploying to production:
- [ ] Change default credentials in `.config/config.yaml`
- [ ] Generate secure JWT secret: `python -c "import secrets; print(secrets.token_urlsafe(64))"`
- [ ] Configure HTTPS with reverse proxy (nginx/Apache)
- [ ] Set up firewall rules (restrict port 8000)
- [ ] Enable rate limiting
- [ ] Configure CORS for production domains
- [ ] Set up log rotation
- [ ] Review and update SMTP settings
- [ ] Test email flow end-to-end

---

## 📚 API Reference

For complete API documentation including endpoints, request/response formats, authentication, WebSocket connections, and usage examples, see **[API_REFERENCE.md](API_REFERENCE.md)**.

Interactive API documentation is also available at:
- **Swagger UI**: `http://localhost:8000/docs`
- **OpenAPI Spec**: `http://localhost:8000/openapi.json`

---

## 🤝 Contributing

We'd love your contributions to make this project even better! Whether it's bug fixes, new features, documentation improvements, or ideas - every contribution is valued and appreciated. Feel free to fork the repository, make your changes, and submit a pull request. Let's build something amazing together!

---

## 🗺️ Roadmap
- [ ] Machine learning-based threat detection
- [ ] Sandbox integration (Hybrid-Analysis, Cuckoo)
- [ ] SOAR platform integration (TheHive, Cortex)
- [ ] Advanced email forensics toolkit
- [ ] Multi-tenant support
- [ ] SIEM integration (Splunk, ELK)

---

<div align="center">

**Built with ❤️ for cybersecurity professionals**

[⬆ Back to Top](#email-security-gateway)

</div>
