# MSF Cloud — Security Exploitation & Education Platform (SSEP)

A full-stack, Dockerized security education platform that simulates Metasploit-style penetration testing in a safe, sandboxed environment. Built for learning offensive security concepts without touching real systems.

> **Disclaimer:** All exploit modules are **simulated**. No real attacks are performed. This platform is designed exclusively for educational purposes and security awareness training.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Environment Variables](#environment-variables)
- [Project Structure](#project-structure)
- [API Reference](#api-reference)
- [Security Model (STRIDE)](#security-model-stride)
- [Testing](#testing)
- [Default Credentials](#default-credentials)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Features

| Module | Description | Access |
|---|---|---|
| **Web Scanner** | AI-simulated URL fingerprinting with technology detection and CVE matching | All users |
| **Exploit Engine** | 12+ simulated attack modules with realistic meterpreter terminal output | All users (some Admin-only) |
| **Exploit Repository** | Browse well-known exploits (EternalBlue, BlueKeep, etc.) and import new modules | All users |
| **Payload Generator** | Simulated msfvenom payload generation with architecture and encoder selection | All users |
| **STRIDE Threat Model** | Interactive view of all six STRIDE categories and their platform mitigations | All users |
| **Audit History** | Tamper-proof PostgreSQL audit trail with CSV export | All users |
| **Admin Panel** | Full user management: role changes, password resets, account deletion | Admin only |

### Simulated Attack Modules

| # | Module | Type | Required Role |
|---|---|---|---|
| 1 | Keylogging (`keyscan`) | Data Exfiltration | SOC Analyst |
| 2 | Screenshot Capture (`screenshot`) | Data Exfiltration | SOC Analyst |
| 3 | Webcam Access (`webcam`) | Data Exfiltration | SOC Analyst |
| 4 | Audio Recording (`mic`) | Data Exfiltration | SOC Analyst |
| 5 | Live Screen Monitoring (`screenshare`) | Data Exfiltration | SOC Analyst |
| 6 | Privilege Escalation (`getsystem`) | System Control | **Admin** |
| 7 | Credential Dumping (`hashdump`) | System Control | **Admin** |
| 8 | Persistence Setup (`persistence`) | System Control | SOC Analyst |
| 9 | File Exfiltration (`download`) | Data Exfiltration | SOC Analyst |
| 10 | Anti-Forensics (`timestomp`) | Evasion | SOC Analyst |
| 11 | Web Scan (`web_scan`) | Reconnaissance | SOC Analyst |
| 12 | Reverse Shell (`reverse_shell`) | Initial Access | SOC Analyst |
| 13 | Payload Generation (`payload`) | Weaponization | SOC Analyst |

---

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│   Browser    │────▶│  Nginx :80   │     │  Metasploit     │
│  (Frontend)  │     │  Static HTML │     │  Framework      │
└─────────────┘     └──────────────┘     │  (Reference)    │
                           │              └─────────────────┘
                           │                      │
                    ┌──────▼──────┐         ┌─────▼─────┐
                    │  Express.js │────────▶│ PostgreSQL │
                    │  API :3000  │         │  :5432     │
                    └─────────────┘         └───────────┘
                    
All services run inside a Docker bridge network (msf_network).
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| **Frontend** | HTML5, Tailwind CSS (CDN), Vanilla JavaScript, JetBrains Mono font |
| **Backend** | Node.js 18, Express.js 4 |
| **Database** | PostgreSQL 15 |
| **Auth** | JWT (jsonwebtoken), bcryptjs (12 salt rounds) |
| **Email** | Nodemailer (Gmail SMTP for verification codes) |
| **Proxy** | Nginx (Alpine) |
| **Container** | Docker Compose |
| **Testing** | Jest + Supertest |

---

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/) (v2+)
- [Node.js 18+](https://nodejs.org/) (only if running outside Docker)
- A Gmail account with an [App Password](https://support.google.com/accounts/answer/185833) (for email verification — optional, codes are logged to console as fallback)

---

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/your-username/metasploit-project.git
cd metasploit-project
```

### 2. Configure environment variables

```bash
cp .env.example .env
```

Edit `.env` and set your own values (see [Environment Variables](#environment-variables)).

### 3. Start all services

```bash
docker compose up -d
```

### 4. Access the platform

| Service | URL |
|---|---|
| **Frontend (Nginx)** | [http://localhost](http://localhost) |
| **Backend API** | [http://localhost:3000](http://localhost:3000) |

### 5. Log in

Use the default admin credentials (see [Default Credentials](#default-credentials)), then **change the password immediately**.

### Stopping

```bash
docker compose down
```

To also remove the database volume:

```bash
docker compose down -v
```

---

## Environment Variables

Copy `.env.example` to `.env` and configure:

| Variable | Description | Default | Required |
|---|---|---|---|
| `DB_HOST` | PostgreSQL hostname | `database` | Yes |
| `DB_USER` | PostgreSQL username | `msf_admin` | Yes |
| `DB_PASSWORD` | PostgreSQL password | — | **Yes** |
| `DB_NAME` | PostgreSQL database name | `metasploit_db` | Yes |
| `JWT_SECRET` | Secret key for signing JWT tokens (use a long random string) | — | **Yes** |
| `MAIL_USER` | Gmail address for sending verification emails | — | No |
| `MAIL_PASS` | Gmail App Password | — | No |
| `DEFAULT_ADMIN_PASSWORD` | Initial admin account password | `admin123` | No |
| `ALLOWED_ORIGIN` | CORS allowed origin | `http://localhost` | No |
| `PORT` | Backend server port | `3000` | No |

> **Note:** If `MAIL_USER`/`MAIL_PASS` are not set, verification codes are printed to the backend console logs instead.

---

## Project Structure

```
metasploit/
├── .env.example            # Template for environment variables
├── .gitignore              # Git ignore rules
├── .dockerignore           # Docker build context exclusions
├── docker-compose.yml      # Multi-container orchestration
├── init.sql                # PostgreSQL schema initialization
├── README.md               # This file
│
├── backend/
│   ├── Dockerfile          # Node.js container build
│   ├── .dockerignore       # Backend-specific Docker exclusions
│   ├── package.json        # Dependencies and scripts
│   ├── package-lock.json   # Locked dependency tree
│   ├── server.js           # Express API server (main application)
│   ├── server.test.js      # Jest test suite
│   └── loot/               # Simulated captured files (gitignored)
│
└── frontend/
    └── index.html          # Single-page application (Tailwind + vanilla JS)
```

---

## API Reference

All endpoints are prefixed with `/api`. Protected endpoints require a `Bearer` token in the `Authorization` header.

### Authentication

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/api/register/init` | No | Start registration (sends email verification code) |
| `POST` | `/api/register/verify` | No | Verify code and complete registration |
| `POST` | `/api/login` | No | Authenticate and receive JWT token |

### Core Operations

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/api/attack` | Yes | Execute a simulated attack module |
| `GET` | `/api/history` | Yes | Retrieve audit log (last 50 entries) |
| `GET` | `/api/health` | No | Health check (returns `{ status: "ok" }`) |

### Public

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/api/users/count` | No | Total registered user count |
| `POST` | `/api/heartbeat` | No | Report user activity, get online count |

### Admin (requires `Admin` role)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/api/admin/users` | Admin | List all users |
| `PUT` | `/api/admin/users/:id/role` | Admin | Change user role (`SOC Analyst` or `Admin`) |
| `PUT` | `/api/admin/users/:id/password` | Admin | Reset a user's password |
| `DELETE` | `/api/admin/users/:id` | Admin | Delete a user account |

### Example: Login

```bash
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'
```

Response:

```json
{
  "success": true,
  "username": "admin",
  "role": "Admin",
  "token": "eyJhbGciOiJIUzI1NiIs..."
}
```

### Example: Execute Module

```bash
curl -X POST http://localhost:3000/api/attack \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"attackType": "keyscan", "targetIp": "10.0.0.1"}'
```

---

## Security Model (STRIDE)

The platform implements mitigations for all six STRIDE threat categories:

| Threat | Description | Mitigation |
|---|---|---|
| **Spoofing** | Impersonating a user | JWT authentication with email verification |
| **Tampering** | Modifying data or code | Input validation, parameterized SQL queries |
| **Repudiation** | Denying an action was performed | Immutable audit logs stored in PostgreSQL |
| **Information Disclosure** | Leaking sensitive data | Docker network isolation, bcrypt password hashing |
| **Denial of Service** | Overloading the system | Express rate limiting (200 requests / 15 minutes) |
| **Elevation of Privilege** | Gaining unauthorized access | JWT-based RBAC with server-side role verification |

### Additional Security Measures

- Passwords hashed with bcrypt (12 salt rounds)
- Email verification with 6-digit OTP (10-minute TTL, max 5 attempts)
- Admin-only access for high-risk modules (`getsystem`, `hashdump`)
- Self-modification prevention (admins cannot change their own role or delete their own account)
- CORS restricted to configured origin
- All user input is validated and sanitized before use

---

## Testing

The project includes a Jest test suite covering authentication, RBAC, input validation, admin operations, and public endpoints.

### Run tests locally

```bash
cd backend
npm install
npm test
```

### Test coverage areas

- **Authentication** — login validation, JWT token generation
- **RBAC & Authorization** — token requirement, role-based module access
- **Input Validation** — attack type whitelist, email format, password complexity
- **Admin User Management** — role changes, password resets, user deletion, self-protection
- **Public Endpoints** — user count, heartbeat

---

## Default Credentials

| Username | Password | Role |
|---|---|---|
| `admin` | `admin123` | Admin |

> **Important:** Change the default admin password immediately after first login. Set `DEFAULT_ADMIN_PASSWORD` in `.env` to a strong password before deployment.

---

## Troubleshooting

### Backend won't connect to the database

```
[CRITICAL] Database Init Error: ...
```

The backend may start before PostgreSQL is ready. Docker Compose `depends_on` ensures ordering but not readiness. The backend will retry on incoming requests. Wait a few seconds and refresh.

### Email verification codes not arriving

If Gmail SMTP is not configured, codes are printed to the backend logs:

```bash
docker compose logs backend | grep FALLBACK
```

### Port conflicts

If port 80 or 3000 is in use, change the port mappings in `docker-compose.yml`:

```yaml
frontend:
  ports:
    - "8080:80"    # Change 80 to 8080

backend:
  ports:
    - "3001:3000"  # Change 3000 to 3001
```

Then update `ALLOWED_ORIGIN` in `.env` and `API_BASE` in `frontend/index.html`.

### Reset everything

```bash
docker compose down -v
docker compose up -d --build
```

This removes the database volume and rebuilds all containers from scratch.

---

## License

This project is for educational purposes only. Use responsibly and only in authorized environments.
