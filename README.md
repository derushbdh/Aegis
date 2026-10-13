# Aegis Security Scanner

![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
![Aiogram 3](https://img.shields.io/badge/Aiogram%203-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white)
![Taskiq](https://img.shields.io/badge/Taskiq-Async%20Tasks-brightgreen?style=for-the-badge)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-316192?style=for-the-badge&logo=postgresql&logoColor=white)
![Redis](https://img.shields.io/badge/redis-%23DD0031.svg?style=for-the-badge&logo=redis&logoColor=white)
![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)
![Qwen 2.5](https://img.shields.io/badge/AI%20Consultant-Qwen%202.5-blueviolet?style=for-the-badge)

Automated black-box DAST (Dynamic Application Security Testing) web vulnerability scanner and Telegram bot powered by an asynchronous engine and a local AI security consultant.

---

## Features

- **Automated DAST Engine:** Comprehensive security audits for web applications without requiring source code access.
- **SSL/TLS Certificate Verification:** Checks certificate validity, remaining expiration days, issuer details, and TLS configuration errors.
- **Security Headers Analyzer:** Evaluates presence and configuration of HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy with safety scoring.
- **Sensitive Files Exposure Detection:** Scans for publicly exposed `.env`, `.git/HEAD`, `docker-compose.yml`, backup archives, and database dumps.
- **HTML Vulnerabilities Analyzer:** Analyzes CSRF, URL and blank links redirect security.
- **Local AI White-Hat Consultant:** Integrates with local LLMs (Qwen 2.5 Coder via LM Studio) to analyze technical scan dumps, prioritize risks, and formulate concrete remediation steps.
- **Audit History & User Persistence:** PostgreSQL persistence powered by SQLAlchemy 2.0 and Alembic migrations tracking scan history and user profiles.
- **Asynchronous Task Architecture:** Distributed, non-blocking scan execution powered by Taskiq and Redis queue broker.

---

## Tech Stack

- **Core & Runtime:** Python 3.11, `asyncio`, `httpx`
- **Bot Framework:** `aiogram 3`
- **Task Queue & Broker:** `taskiq`, `taskiq-redis`, `Redis 7`
- **Database & Migrations:** `PostgreSQL 15`, `SQLAlchemy 2.0 (asyncpg)`, `Alembic`
- **AI Integration:** OpenAI API Client (Local LM Studio with Qwen 2.5 Coder)
- **Containerization:** Docker & Docker Compose

---

## Quick Start

### 1. Clone & Configure

```bash
git clone https://github.com/derushbdh/Aegis.git
cd Aegis
cp .env.example .env
```

Fill in your `BOT_TOKEN` and database credentials in `.env`.

### 2. Run Infrastructure (PostgreSQL + Redis)

```bash
docker compose up -d
```

### 3. Run Migrations

```bash
alembic upgrade head
```

### 4. Start the Bot

```bash
python -m src.bot.main
```
