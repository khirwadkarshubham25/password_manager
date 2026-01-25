# 🔐 Password Manager

A secure, full-stack password management application built with Django. Store, manage, and retrieve passwords with enterprise-grade encryption.

## ✨ Features

✅ **User Authentication**
- User registration with email validation
- Secure JWT login with token refresh
- Automatic session management (up to 60 minutes)
- No re-login needed during session

✅ **Password Management**
- Create, read, update, delete passwords (CRUD)
- Store platform, email, URL, and password
- Copy-to-clipboard functionality
- Real-time statistics

✅ **Security** 
- PBKDF2 + Fernet encryption for passwords
- JWT authentication (20-minute tokens, 60-minute refresh)
- CSRF protection on all requests
- XSS prevention with HTML escaping
- HTTPS/TLS ready for production

---

## 🛠 Tech Stack

| Component | Technology |
|-----------|-----------|
| **Backend** | Django 4.x, Django REST Framework |
| **Authentication** | PyJWT (JWT tokens) |
| **Encryption** | Fernet + PBKDF2 |
| **Database** | SQLite3 (dev), PostgreSQL (prod) |
| **Frontend** | HTML5, CSS3, Vanilla JavaScript |
| **Server** | Gunicorn (production) |

---

## 📋 Prerequisites

- **Python 3.8+**
- **pip** package manager
- **Git** for version control
- **Modern web browser**

---

## 🚀 Quick Start

### 1. Clone & Setup
```bash
git clone https://github.com/yourusername/password-manager.git
cd password-manager
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
```

### 2. Install & Configure
```bash
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your settings
```

### 3. Initialize Database
```bash
python manage.py migrate
python manage.py runserver
```

Visit: `http://localhost:8000`

---

## 💻 Usage

### Register
1. Navigate to `/register`
2. Create account with username, email, password
3. Password must be 8+ characters with complexity

**[SCREENSHOT: Registration Page - Add screenshot here]**

---

### Login
1. Go to `/login`
2. Enter credentials
3. Tokens stored in localStorage automatically
4. Session lasts up to 60 minutes with auto-refresh

**[SCREENSHOT: Login Page - Add screenshot here]**

---

### Manage Passwords
- **Add:** Click "Add New Password" → Fill form → Save
- **Edit:** Click "Edit" → Change password only → Update
- **Copy:** Click "Copy" → Password in clipboard
- **Delete:** Click "Delete" → Confirm

**[SCREENSHOT: Dashboard - Password List - Add screenshot here]**

**[SCREENSHOT: Add/Edit Password Modal - Add screenshot here]**

---

### Logout
Click "Logout" → Tokens cleared → Redirected to login

---

## 📡 API Endpoints

### Authentication
```bash
POST /register
{
    "username": "john_doe",
    "first_name": "John",
    "last_name": "Doe",
    "email": "john@example.com",
    "password": "SecurePass123!"
}

POST /login
{
    "username": "john_doe",
    "password": "SecurePass123!"
}
Response: api_token, refresh_token, expiry times

POST /refresh_token
{
    "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
}
Response: new api_token, new refresh_token
```

### Password Management
```bash
GET /manage_password?user_id=1
Authorization: Bearer <api_token>

POST /manage_password
{
    "user_id": 1,
    "platform": "Gmail",
    "email": "user@gmail.com",
    "url": "https://mail.google.com",
    "password": "encrypted_password"
}

PUT /manage_password
{
    "user_password_id": 1,
    "password": "new_password"
}

DELETE /manage_password
{
    "user_password_id": 1
}
```

---

## 🔐 Security Features

### Encryption
- **Algorithm:** Fernet (AES-128 in CBC mode)
- **Master Password:** PBKDF2 hashed with SHA256
- **Password Storage:** Encrypted in database
- **Decryption:** Only for authenticated users

### Authentication
- **JWT Tokens:** HS256 signed with SECRET_KEY
- **API Token:** 20 minutes (short-lived)
- **Refresh Token:** 60 minutes (longer-lived)
- **Auto-Refresh:** Tokens refreshed automatically in background
- **Token Rotation:** New tokens issued on each refresh (prevents reuse)

### CSRF Protection
- CSRF token required for all state-changing requests
- Token regenerated on each request
- SameSite=Lax cookie attribute

### XSS Prevention
- HTML content escaped
- Input validation on all fields
- Content-Type headers set properly

### Production Security
- Enable HTTPS/SSL
- Set DEBUG=False
- Configure CSRF_COOKIE_SECURE=True
- Use strong SECRET_KEY (50+ characters)
- Configure ALLOWED_HOSTS to specific domains
- Use PostgreSQL instead of SQLite

---

## ⚙️ Configuration

### Environment Variables
```env
# Required
SECRET_KEY=your-super-secret-key-minimum-64-chars
DEBUG=False (production)
ALLOWED_HOSTS=example.com,www.example.com

# Security
CSRF_TRUSTED_ORIGINS=https://example.com,https://www.example.com
CSRF_COOKIE_SECURE=True (production)
CSRF_COOKIE_SAMESITE=Strict (production)

# Database
DATABASE_URL=postgresql://user:password@localhost/dbname
```

### Token Expiry
```python
API_TOKEN_EXPIRY = 20 minutes  # Access token
REFRESH_TOKEN_EXPIRY = 60 minutes  # Session duration
```

Modify in: `password_manager/commons/generic_constants.py`

---

## 🧪 Testing

### Manual Testing
```bash
# Test token refresh
1. Login → Wait 20+ minutes
2. Click any operation → Token refreshes automatically
3. Check browser console: "API token expired or expiring soon, refreshing..."

# Test CSRF protection
curl -X POST http://localhost:8000/manage_password \
  -H "Authorization: Bearer <token>"
# Should fail: 403 CSRF token missing

# Test XSS prevention
Try to inject: <script>alert('xss')</script>
# Should be escaped/sanitized

# Test authentication
curl http://localhost:8000/dashboard
# Should redirect to /login
```

---

## 🔐 Security Best Practices

### For Users
- Never share your password with anyone
- Use unique, strong passwords
- Keep your browser updated
- Use HTTPS connections only
- Don't use on public/shared computers

### For Developers
- Never commit `.env` file
- Generate new SECRET_KEY for production
- Use environment variables for secrets
- Keep dependencies updated
- Run security tests regularly

### Reporting Security Issues
**Do NOT create public issues for security vulnerabilities.**

Email: `security@example.com`

Include:
- Description of vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

Response time: 48 hours

---

## 📁 Project Structure

```
password-manager/
├── password_manager/              # Main Django project
│   ├── settings.py               # Configuration (env vars)
│   ├── urls.py
│   └── services/
│       └── view_services.py      # Service factory
│
├── password_vault_manager/        # Main app
│   ├── models.py                 # Database models
│   ├── views.py                  # Django views
│   ├── urls.py
│   ├── services/                 # Business logic
│   │   ├── register_user_service.py
│   │   ├── login_user_service.py
│   │   ├── refresh_token_service.py
│   │   ├── crypto_service.py
│   │   └── password_*.py
│   ├── utils/
│   │   └── token_verifier.py    # JWT validation
│   ├── validators/
│   │   ├── email_validator.py
│   │   ├── password_validator.py
│   │   └── username_validator.py
│   └── templates/
│       ├── register.html
│       ├── login.html
│       └── dashboard.html
│
├── .env.example
├── .gitignore
├── requirements.txt
├── README.md
├── SECURITY.md
├── CONTRIBUTING.md
└── manage.py
```

---

## 🤝 Contributing

### Setup Development Environment
```bash
git clone <your-fork>
cd password-manager
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Code Style
- **Python:** PEP 8 (use `black` formatter)
- **JavaScript:** ES6+, semicolons optional
- **Git commits:** Use imperative mood with emoji
  - ✨ New feature
  - 🐛 Bug fix
  - 📚 Documentation
  - 🔐 Security improvement

### Pull Request Process
1. Fork repository
2. Create feature branch: `git checkout -b feature/your-feature`
3. Make changes and test
4. Commit: `git commit -m "✨ Add: feature description"`
5. Push: `git push origin feature/your-feature`
6. Create Pull Request with detailed description

---

## 🆘 Troubleshooting

### Token Refresh Not Working
- Verify CSRF token in meta tag
- Check refresh_token in localStorage
- Clear browser cookies and retry
- Check `/refresh_token` endpoint is accessible

### CSRF Token Mismatch
- Ensure CSRF token is current
- Check CSRF_TRUSTED_ORIGINS setting
- Verify CSRF_COOKIE_SECURE matches protocol
- Clear cookies and retry

### Login Fails
- Verify database migrations ran: `python manage.py migrate`
- Check username/password are correct
- Check database has the user
- Check server logs for errors

### Password Won't Decrypt
- Verify SECRET_KEY hasn't changed
- Check encryption service is functioning
- Ensure database hasn't been corrupted
- Try re-adding the password

---

## 📄 License

MIT License - See [LICENSE](LICENSE) file

---

## 🎯 Roadmap

### v1.0 (Current) ✅
- User authentication ✓
- Password CRUD ✓
- JWT token refresh ✓
- CSRF protection ✓

### v1.1 (Planned)
- Password strength meter
- Two-factor authentication
- Audit logs
- Password sharing

### v2.0 (Future)
- Mobile app (iOS/Android)
- Browser extension
- Team collaboration
- Advanced encryption options