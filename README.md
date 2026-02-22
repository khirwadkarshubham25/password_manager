# 🔐 Password Manager

A secure, full-stack enterprise password management system built with Django. Features a user-facing vault for storing and managing credentials, and a fully separate admin panel for managing users, roles, policies, breach databases, and audit logs.

---

## ✨ Features

### 👤 User Authentication
- Email-based registration with validation
- Secure JWT login with automatic token refresh
- Sessions up to 60 minutes with silent auto-refresh
- Role-based access control (Admin / User)

### 🔑 Password Vault (Users)
- Create, read, update, delete passwords (CRUD)
- Store platform, email, URL, and encrypted password
- Copy-to-clipboard — password never displayed on screen
- Auto-generate secure passwords based on assigned policy
- Policy violation warnings on save (without blocking)
- Breach detection warnings on save (without blocking)
- Password history tracking to prevent reuse

### 🛡️ Admin Panel
- **User Management** — create, update, delete users; assign roles
- **Role Management** — create and manage roles
- **Password Policies** — define complexity, length, entropy, history rules
- **Policy Assignments** — assign policies to individual users
- **Breach Databases** — manage breach sources (currently HIBP; additional databases planned)
- **Breached Hashes** — view and query breached password hashes
- **Policy Violations** — view per-user violation history with full details
- **Audit Logs** — immutable log of all admin actions

### 🔒 Security
- **Application-layer encryption** — Fernet (AES-128 CBC) + PBKDF2/SHA-256
- **JWT authentication** — 20-minute access tokens, 60-minute refresh tokens
- **k-Anonymity breach checking** — HIBP integration (only first 5 SHA-1 chars sent; additional breach sources planned)
- **Policy enforcement** — length, complexity, entropy, personal info, history checks
- **CSRF protection** on all state-changing requests
- **XSS prevention** with HTML escaping
- **HTTPS/TLS ready** for production

---

## 🛠 Tech Stack

| Component | Technology |
|---|---|
| **Backend** | Django 4.x, Django REST Framework |
| **Authentication** | PyJWT (HS256 JWT tokens) |
| **Encryption** | Fernet + PBKDF2/SHA-256 |
| **Breach Detection** | HIBP k-Anonymity API (additional sources planned) |
| **Database** | SQLite3 (dev) · PostgreSQL (prod) |
| **Frontend** | HTML5, CSS3, Vanilla JavaScript |
| **Server** | Gunicorn (production) |

---

## 📋 Prerequisites

- **Python 3.10+**
- **pip** package manager
- **Git** for version control
- **Modern web browser**

---

## 🚀 Quick Start

### 1. Clone & Set Up Environment
```bash
git clone https://github.com/yourusername/password-manager.git
cd password-manager
python3 -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate
```

### 2. Install Dependencies & Configure
```bash
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your settings (see Configuration section below)
```

### 3. Generate Fernet Encryption Key
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# Paste the output into ENCRYPTION_KEY in your .env
```

### 4. Run Migrations & Start Server
```bash
python manage.py migrate
python manage.py runserver
```

| Interface | URL |
|---|---|
| User Login | `http://localhost:8000/accounts/login` |
| User Register | `http://localhost:8000/accounts/register` |
| User Vault | `http://localhost:8000/vault/dashboard` |
| Admin Panel | `http://localhost:8000/admin-panel/admin-dashboard` |

---

## 💻 Usage

### Register & Login
1. Navigate to `/accounts/register`
2. Create an account with first name, last name, email, and password
3. Login at `/accounts/login` — tokens are stored in `localStorage` automatically
4. Sessions last up to 60 minutes with silent auto-refresh

### User Vault
- **Add Password** — Click "Add Password" → Fill platform, URL, email, password → Save
- **Generate Password** — Click ⚡ in the modal to auto-generate based on your assigned policy
- **Copy Password** — Click "Copy" on any row — password never appears on screen
- **Edit** — Click "Edit" → Update any field → Save (policy + breach checks run again)
- **Delete** — Click "Delete" → Confirm

Policy violations and breach warnings appear **inline after saving** — the entry is always saved regardless, but warnings are shown so users can take action.

### Admin Panel
1. Login with an admin account (role_id = 1)
2. Manage users, assign policies, configure breach databases
3. Monitor policy violations and audit logs

---

## 📡 API Endpoints

All API endpoints require `Authorization: Bearer <api_token>` unless noted.

### 🔑 Authentication — `/accounts/`
```
POST   /accounts/api/login              Login, returns api_token + refresh_token
POST   /accounts/api/register           Register new user
```

### 🏛️ Admin — `/admin-panel/`

**Users**
```
GET    /admin-panel/api/users                  List users (paginated, sortable)
POST   /admin-panel/api/users                  Create user
PUT    /admin-panel/api/users                  Update user
DELETE /admin-panel/api/users                  Delete user
GET    /admin-panel/api/user-details           Get user details
```

**Roles**
```
GET    /admin-panel/api/roles                  List roles
POST   /admin-panel/api/roles                  Create role
PUT    /admin-panel/api/roles                  Update role
DELETE /admin-panel/api/roles                  Delete role
```

**Password Policies**
```
GET    /admin-panel/api/policies               List policies (paginated)
POST   /admin-panel/api/policies               Create policy
PUT    /admin-panel/api/policies               Update policy
DELETE /admin-panel/api/policies               Delete policy
GET    /admin-panel/api/policy-details         Get policy details
```

**Policy Assignments**
```
GET    /admin-panel/api/assignments            List assignments
POST   /admin-panel/api/assignments            Assign policy to user
PUT    /admin-panel/api/assignments            Update assignment
DELETE /admin-panel/api/assignments            Remove assignment
GET    /admin-panel/api/assignment-details     Get assignment details
```

**Breach Databases**
```
GET    /admin-panel/api/breach-databases       List breach databases
POST   /admin-panel/api/breach-databases       Add breach database
PUT    /admin-panel/api/breach-databases       Update breach database
DELETE /admin-panel/api/breach-databases       Delete breach database
GET    /admin-panel/api/breach-database-details  Get details
```

**Breached Hashes**
```
GET    /admin-panel/api/breached-hashes        List breached hashes (read-only)
GET    /admin-panel/api/breached-hash-details  Get hash details (read-only)
```

**Policy Violations**
```
GET    /admin-panel/api/policy-violations      List user violations (filterable by user, severity, category)
GET    /admin-panel/api/policy-violation-details  Get violation details
```

**Audit Logs**
```
GET    /admin-panel/api/audit-logs             List audit logs (read-only)
GET    /admin-panel/api/audit-log-details      Get log details (read-only)
```

### 🔐 Vault — `/vault/`
```
GET    /vault/api/user-passwords               List user's passwords (paginated, searchable)
POST   /vault/api/user-passwords               Create password entry
PUT    /vault/api/user-passwords               Update password entry
DELETE /vault/api/user-passwords               Delete password entry
GET    /vault/api/generate-password            Generate password based on assigned policy
```

---

## 🔐 Security Features

### Encryption
- **Algorithm:** Fernet (AES-128 in CBC mode with HMAC-SHA256)
- **Key Derivation:** PBKDF2/SHA-256 with 100,000 iterations
- **Per-user encryption:** Passwords encrypted using each user's hashed master password
- **Decryption:** Only possible for the authenticated user

### Authentication
- **JWT Tokens:** HS256 signed with `SECRET_KEY`
- **API Token:** 20-minute lifetime (short-lived access)
- **Refresh Token:** 60-minute lifetime (session duration)
- **Auto-Refresh:** Tokens refreshed silently in the background
- **Token Rotation:** New tokens issued on each refresh (prevents reuse)

### Breach Detection
- **HIBP k-Anonymity:** Only the first 5 characters of the SHA-1 hash are sent to HIBP — the full hash never leaves the server
- **Local caching:** Breached hashes stored in `BreachedPasswordHash` table; subsequent checks skip the live API call
- **Extensible architecture:** The `BreachDatabase` model and `CreateBreachedPasswordHashService` are designed to support additional breach sources — custom databases with API_KEY and BASIC authentication are already modelled and planned for a future release

### Policy Enforcement
Every password save (create or update) checks:

| Rule | Violation Code |
|---|---|
| Minimum / maximum length | `PWD_TOO_SHORT` / `PWD_TOO_LONG` |
| Uppercase required | `PWD_NO_UPPERCASE` |
| Lowercase required | `PWD_NO_LOWERCASE` |
| Digits required | `PWD_NO_DIGIT` |
| Special characters required | `PWD_NO_SPECIAL_CHAR` |
| Minimum complexity types | `PWD_LOW_COMPLEXITY` |
| Shannon entropy threshold | `PWD_LOW_ENTROPY` |
| Contains email address | `PWD_CONTAINS_EMAIL` |
| Contains user's name | `PWD_CONTAINS_NAME` |
| Recently used (history) | `PWD_REUSED` |

Violations are **warned, not blocked** — entries are always saved, but violations are recorded in `PolicyViolation` and returned in the API response.

---

## ⚙️ Configuration

### Environment Variables (`.env`)
```env
# Django core
DJANGO_SECRET_KEY=your-super-secret-key-minimum-64-chars
DJANGO_DEBUG=False
DJANGO_ALLOWED_HOSTS=example.com,www.example.com

# Application-layer encryption key (generate with Fernet.generate_key())
ENCRYPTION_KEY=your-fernet-key-here

# Production security
CSRF_TRUSTED_ORIGINS=https://example.com
CSRF_COOKIE_SECURE=True
CSRF_COOKIE_SAMESITE=Strict

# Database (production)
DATABASE_URL=postgresql://user:password@localhost/dbname
```

---

## 📁 Project Structure

```
password-manager/
├── manage.py
├── requirements.txt
├── .env.example
├── .gitignore
│
├── password_manager/                  # Django project config
│   ├── settings.py
│   ├── urls.py
│   ├── commons/
│   │   ├── generic_constants.py       # App-wide constants & messages
│   │   ├── commons.py                 # Shared utilities
│   │   └── token_verifier.py          # JWT validation decorator
│   └── services/
│       ├── base_service.py            # Abstract base service
│       ├── crypto_service.py          # Fernet + PBKDF2 encryption
│       └── view_services.py           # Service registry / factory
│
├── accounts/                          # Auth app
│   ├── models.py                      # Users, Role, UserProfile
│   ├── views.py
│   ├── urls.py
│   ├── services/
│   │   ├── login_user_service.py
│   │   ├── register_user_service.py
│   │   └── service_helper/
│   └── templates/
│       ├── login.html
│       └── register.html
│
├── admin_panel/                       # Admin management app
│   ├── models.py                      # AuditLog, PasswordPolicy, PolicyAssignment,
│   │                                  # PolicyViolation, BreachDatabase, BreachedPasswordHash
│   ├── views.py
│   ├── urls.py
│   ├── services/
│   │   ├── create_user_service.py
│   │   ├── create_policy_service.py
│   │   ├── create_assignment_service.py
│   │   ├── create_breach_database_service.py
│   │   ├── get_policy_violations_service.py
│   │   ├── get_audit_logs_service.py
│   │   └── ...                        # Full CRUD services for each model
│   └── templates/
│       ├── admin_base.html
│       ├── dashboard.html
│       ├── users.html
│       ├── roles.html
│       ├── policies.html
│       ├── assignment.html
│       ├── breach.html
│       ├── policy_violations.html
│       └── audit_logs.html
│
└── vault/                             # User password vault app
    ├── models.py                      # UserPasswords, UserPasswordHistory
    ├── views.py
    ├── urls.py
    ├── services/
    │   ├── create_user_password_service.py
    │   ├── update_user_password_service.py
    │   ├── delete_user_password_service.py
    │   ├── get_user_passwords_service.py
    │   ├── generate_password_service.py
    │   ├── create_breached_password_hash_service.py
    │   ├── create_password_policy_violation_service.py
    │   └── service_helper/
    └── templates/
        └── dashboard.html
```

---

## 🧪 Testing

### Manual Testing
```bash
# Verify migrations
python manage.py migrate

# Test authentication flow
# 1. Register at /accounts/register
# 2. Login at /accounts/login
# 3. Check localStorage for api_token and refresh_token

# Test breach detection
# Create a password entry using a known breached password (e.g. "password123")
# Response should include breach_warning with source details

# Test policy violation
# Create an entry with a weak password (e.g. "abc")
# Response should include policy_warning listing each violation

# Test token auto-refresh
# Login → wait 20+ minutes → perform any vault action
# Token refreshes silently; check browser console for refresh logs

# Test CSRF protection
curl -X POST http://localhost:8000/accounts/api/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"test"}'
# Should succeed (CSRF exempt on API endpoints)

# Test auth guard
curl http://localhost:8000/vault/api/user-passwords
# Should return 401 Unauthorized
```

---

## 🆘 Troubleshooting

### Passwords Won't Decrypt
- Verify `ENCRYPTION_KEY` in `.env` has not changed since the passwords were saved
- Fernet keys are 44-character base64 strings — regenerating one invalidates all existing encrypted data

### Migration Errors
```bash
python manage.py showmigrations      # Check migration state
python manage.py migrate --run-syncdb
```

### CSRF Token Mismatch
- Verify `CSRF_TRUSTED_ORIGINS` includes your domain
- Check `CSRF_COOKIE_SECURE=True` only when serving over HTTPS
- Clear cookies and retry

### Breach Check Fails
- HIBP requires internet access — verify outbound requests are not blocked
- Check `requests` is installed: `pip install requests`
- If you have configured additional breach databases, verify their `source_url` and authentication credentials in the admin panel

---

## 🔐 Security Best Practices

### For Users
- Use the ⚡ Generate button — it creates passwords that comply with your assigned policy
- Never reuse passwords across platforms
- Use HTTPS connections only
- Log out on shared or public computers

### For Developers
- Never commit `.env` to version control
- Generate a fresh `SECRET_KEY` and `ENCRYPTION_KEY` for every deployment
- Set `DJANGO_DEBUG=False` in production
- Use PostgreSQL in production (not SQLite)
- Run `pip install --upgrade -r requirements.txt` regularly

### Reporting Security Issues
**Do NOT create public GitHub issues for security vulnerabilities.**

Email: `security@example.com`

Please include: description, steps to reproduce, potential impact, and suggested fix.
Response time: 48 hours.

---

## 🎯 Roadmap

### v1.0 (Current) ✅
- User authentication & JWT sessions ✓
- Password vault with full CRUD ✓
- Fernet application-layer encryption ✓
- Policy engine (length, complexity, entropy, history, personal info) ✓
- HIBP breach detection with k-Anonymity ✓
- Admin panel (users, roles, policies, assignments, breaches, violations, audit logs) ✓
- Password generation based on assigned policy ✓

### v1.1 (Planned)
- Two-factor authentication (TOTP)
- Password strength meter in vault UI
- Email notifications for breach detections
- Bulk policy assignment
- Dictionary word detection
- Keyboard pattern detection (e.g. `qwerty`, `123456`)
- Additional breach database integrations (custom APIs beyond HIBP)

### v2.0 (Future)
- Browser extension
- Mobile app (iOS / Android)
- Team / organisation vaults
- Advanced anomaly detection
