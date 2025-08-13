# 🗳️ Secure E-Voting System with Blind Signature

[![Security](https://img.shields.io/badge/Security-Penetration%20Tested-green)](https://s.id/InvictiScanReport)
[![Code Quality](https://img.shields.io/badge/Code%20Quality-DeepSource%20Analyzed-blue)](https://s.id/DeepSourceScanResult)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

## 📋 Table of Contents
- [🎯 Overview](#-overview)
  - [🔐 Key Cryptographic Concepts](#-key-cryptographic-concepts)
- [✨ Features](#-features)
  - [🛡️ Security Features](#️-security-features)
  - [🎨 User Experience](#-user-experience)
- [🏗️ Architecture](#️-architecture)
  - [📁 Project Structure](#-project-structure)
- [📦 Installation](#-installation)
  - [Prerequisites](#prerequisites)
  - [Option 1: Local Development Setup](#option-1-local-development-setup)
  - [Option 2: Docker Deployment](#option-2-docker-deployment)
  - [Option 3: Production Deployment](#option-3-production-deployment)
  - [Key URLs and Endpoints](#key-urls-and-endpoints)
- [🔒 Security](#-security)
  - [Penetration Testing Results](#penetration-testing-results)
  - [Code Quality Analysis](#code-quality-analysis)
  - [Security Measures Implemented](#security-measures-implemented)
- [⚡ Performance Benchmarks](#-performance-benchmarks)
  - [vs zkVoting Research Baseline](#vs-zkvoting-research-baseline)
  - [Performance Features](#performance-features)
- [📄 License](#-license)
- [🙏 Acknowledgments](#-acknowledgments)

## 🎯 Overview

A secure electronic voting system implementing **RSA-based Blind Signature** scheme to ensure voter anonymity while maintaining vote authenticity. This system addresses the critical challenges of **authentication** and **privacy** in digital voting through cryptographic protocols.

### 🔐 Key Cryptographic Concepts

**Digital Signature**: Authenticates voter identity and ensures message integrity by encrypting the hash of the message with the sender's private key.

**Blind Signature**: Enables privacy-preserving authentication where an official can verify voter eligibility without seeing the actual vote content. The message is disguised (blinded) before signing and can be publicly verified against the original message.

## ✨ Features

### 🛡️ Security Features
- **RSA-based Blind Signature** scheme for vote anonymity
- **Digital signature** verification for voter authentication
- **CSRF protection** against cross-site request forgery
- **SQL injection prevention** with parameterized queries
- **Session management** with secure tokens
- **Rate limiting** to prevent DoS attacks
- **Audit logging** for election integrity

### 🎨 User Experience
- **Responsive** web interface (HTML/CSS/JavaScript)
- **Real-time** progress indicators
- **Intuitive** voting workflow
- **Comprehensive** admin dashboard
- **Mobile-friendly** design

## 🏗️ Architecture

```
┌─────────────┐    ┌─────────────────┐    ┌──────────────────┐
│   Voter     │───▶│  Web Interface  │───▶│  Flask Backend   │
└─────────────┘    └─────────────────┘    └──────────────────┘
                            │                        │
                            ▼                        ▼
                   ┌─────────────────┐    ┌──────────────────┐
                   │ Blind Signature │───▶│ SQLite Database  │
                   │     Module      │    └──────────────────┘
                   └─────────────────┘
```

### 📁 Project Structure

```
secure-evoting-system/
├── 📄 app.py                    # Main Flask application
├── 📊 benchmark_tabulation.py   # Performance benchmarking script
├── 🐳 docker-compose.yml        # Docker configuration
├── 🐳 Dockerfile               # Docker build configuration
├── 📋 requirements.txt          # Python dependencies
├── 🔒 dev.certificate.crt       # SSL certificate
├── 🔑 dev.private.key          # SSL private key
├── 📚 README.md                # This documentation
├── 📁 core/                    # Core modules
│   ├── 🔐 BlindSig.py          # Blind signature implementation
│   ├── 🗄️ createdb.py          # Database initialization
│   ├── 📊 benchmark_tabulasi.py # Legacy benchmark module
│   ├── ⚡ ultra_fast_recap.py   # Ultra-optimized tabulation
│   ├── 📊 Recap.py             # Standard vote tabulation
│   ├── 🔑 key_manager.py       # RSA key management
│   ├── 🔢 cryptomath.py        # Cryptographic utilities
│   ├── 🌐 templates/           # HTML templates
│   │   ├── base.html
│   │   ├── index.html
│   │   ├── vote.html
│   │   ├── login.html
│   │   ├── benchmark.html
│   │   └── recap.html
│   └── 🎨 static/              # CSS, JS, images
│       ├── style.css
│       ├── voting_process.png
│       └── uploads/            # User uploaded files
├── 📁 config/                  # Configuration files
│   └── .env                    # Environment variables
├── 📁 tests/                   # Test modules (if available)
└── 📁 static/                  # Legacy static files
```

## 📦 Installation

### Prerequisites
- **Python 3.8+** (Recommended: Python 3.11 or newer)
- **pip** package manager
- **Git** for cloning repository
- **OpenSSL** (for SSL certificates)
- **Docker & Docker Compose** (optional, for containerized deployment)

### Option 1: Local Development Setup

#### Step 1: Clone Repository
```bash
git clone https://github.com/RakhaMaulana/Bismillah_TA.git
cd Bismillah_TA
```

#### Step 2: Create Virtual Environment (Recommended)
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

#### Step 3: Install Dependencies
```bash
# Upgrade pip first
pip install --upgrade pip

# Install all required packages
pip install -r requirements.txt
```

#### Step 4: Set Up Environment Configuration
```bash
# Environment variables are already configured in config/.env
# You can modify config/.env if needed
echo "Configuration file located at: config/.env"
```

#### Step 5: Generate SSL Certificates
```bash
# Generate self-signed SSL certificate for HTTPS
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 \
  -nodes -keyout dev.private.key -out dev.certificate.crt \
  -subj "/CN=Pemilihan Umum Taruna" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:0.0.0.0"

# On Windows PowerShell, use:
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes -keyout dev.private.key -out dev.certificate.crt -subj "/CN=Pemilihan Umum Taruna"
```

#### Step 6: Run Application
```bash
# Start the Flask application
python app.py

# Or for development with auto-reload:
python -m flask run --host=0.0.0.0 --port=5001 --cert=dev.certificate.crt --key=dev.private.key
```

**🌐 Access the application:**
- Main application: `https://localhost:5001` or `https://[your-ip]:5001`
- Admin login: `https://localhost:5001/login`
  - Username: `AdminKitaBersama`
  - Password: `AdminKitaBersama`

### Option 2: Docker Deployment

#### Prerequisites for Docker
```bash
# Verify Docker installation
docker --version
docker-compose --version

# If not installed, download from: https://www.docker.com/
```

#### Step 1: Clone and Prepare
```bash
git clone https://github.com/RakhaMaulana/Bismillah_TA.git
cd Bismillah_TA
```

#### Step 2: Generate SSL Certificates
```bash
# Generate SSL certificates for Docker
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 \
  -nodes -keyout dev.private.key -out dev.certificate.crt \
  -subj "/CN=Pemilihan Umum Taruna" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:0.0.0.0"
```

#### Step 3: Build and Run with Docker Compose
```bash
# Build the Docker images
docker-compose build

# Start the services
docker-compose up -d

# View logs (optional)
docker-compose logs -f

# Stop the services
docker-compose down
```

#### Step 4: Access Dockerized Application
- **Main application**: `https://localhost:5001`
- **Admin panel**: `https://localhost:5001/login`
- **Benchmark interface**: `https://localhost:5001/benchmark`

#### Docker Management Commands
```bash
# View running containers
docker-compose ps

# Restart services
docker-compose restart

# View logs
docker-compose logs app

# Access container shell
docker-compose exec app bash

# Clean up everything
docker-compose down --volumes --remove-orphans
docker system prune -a
```

### Option 3: Production Deployment

#### Using Gunicorn (Recommended for Production)
```bash
# Install Gunicorn
pip install gunicorn

# Run with Gunicorn
gunicorn --bind 0.0.0.0:5001 \
         --workers 4 \
         --timeout 120 \
         --certfile=dev.certificate.crt \
         --keyfile=dev.private.key \
         app:app
```

#### Using Nginx + Gunicorn
```bash
# Install and configure Nginx as reverse proxy
# Create /etc/nginx/sites-available/evoting
server {
    listen 443 ssl;
    server_name your-domain.com;

    ssl_certificate /path/to/dev.certificate.crt;
    ssl_certificate_key /path/to/dev.private.key;

    location / {
        proxy_pass http://127.0.0.1:5001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Key URLs and Endpoints
- **Main page**: `https://localhost:5001/`
- **Voter registration**: `https://localhost:5001/register_voter`
- **Vote submission**: `https://localhost:5001/submit_token`
- **Admin login**: `https://localhost:5001/login`
- **Results tabulation**: `https://localhost:5001/recap`
- **Performance benchmark**: `https://localhost:5001/benchmark`
- **Voter status**: `https://localhost:5001/voter_status`

## 🔒 Security

### Penetration Testing Results
- **Invicti Security Scanner**:
[View Report](https://s.id/InvictiScanReport)
  ![Invicti Results](Pengujian/Hasil%20Pengujian%20Keamanan/Bukti%20INvicti.png)

- **Burp Suite Professional**:
[View Report](https://s.id/DeepScanBurpSuite)
  ![Burp Suite Results](Pengujian/Hasil%20Pengujian%20Keamanan/Bukti%20Burpsuite.png)

### Code Quality Analysis
- **DeepSource Static Analysis**:
[View Report](https://s.id/DeepSourceScanResult)
  ![DeepSource Results](Pengujian/Hasil%20Pengujian%20Keamanan/Bukti%20Deepsource.png)

### Security Measures Implemented
- ✅ **OWASP Top 10** compliance verified
- ✅ **SQL Injection** protection with parameterized queries
- ✅ **XSS Prevention** with output encoding
- ✅ **CSRF Protection** with secure tokens
- ✅ **Authentication** bypass prevention
- ✅ **Session management** security
- ✅ **Input validation** and sanitization

## ⚡ Performance Benchmarks

### vs zkVoting Research Baseline

| Metric | Our System | zkVoting | Improvement |
|--------|------------|----------|-------------|
| **Vote Casting** | ~69ms | 2300ms | **33.5x faster** |
| **Tabulation** | ~0.2ms/ballot | 3.9ms/ballot | **19.5x faster** |
| **Overall E2E** | ~69ms/vote | ~2300ms/vote | **33.4x faster** |
| **Throughput** | 1000+ votes/hour | ~30 votes/hour | **35x higher** |

### Performance Features
- 🚀 **Sub-100ms** vote processing
- 📊 **Real-time** tabulation
- 🔄 **Concurrent** vote handling
- 💾 **Optimized** database queries
- ⚡ **Scalable** architecture

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **RSA Cryptography** research and implementation
- **Blind Signature** scheme development
- **zkVoting** research for performance comparison
- **OWASP** security guidelines and best practices
- **Flask** web framework and community

**⚠️ Security Notice**: This system is designed for educational and research purposes. For production elections, please conduct thorough security audits and compliance reviews.

**🚀 Performance Note**: Benchmark results may vary based on hardware specifications and network conditions. Test in your target environment for accurate measurements. Our test was using i7-10750H with 16GB RAM


