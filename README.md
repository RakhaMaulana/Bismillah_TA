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

### 🚀 Quick Start (Recommended)

**The easiest way to get started! Our startup scripts handle everything automatically.**

#### Windows Users:
```batch
# Clone the repository
git clone https://github.com/RakhaMaulana/Bismillah_TA.git
cd Bismillah_TA

# Run the automated setup script
start.bat

# For Docker deployment:
start.bat docker

# For help with script options:
start.bat --help
```

#### Linux/macOS Users:
```bash
# Clone the repository
git clone https://github.com/RakhaMaulana/Bismillah_TA.git
cd Bismillah_TA

# Make script executable and run
chmod +x start.sh
./start.sh

# For Docker deployment:
./start.sh docker

# For help with script options:
./start.sh --help
```

**📋 What the startup scripts do:**
- ✅ **Verify Prerequisites**: Check Python, pip, and Docker (if needed)
- ✅ **Environment Setup**: Create and activate virtual environment automatically
- ✅ **Smart Dependencies**: Install packages with fallback options for compatibility
- ✅ **Database Initialization**: Setup SQLite database if not exists
- ✅ **SSL Configuration**: Copy SSL certificates for HTTPS
- ✅ **Environment Variables**: Configure secure defaults automatically
- ✅ **Application Launch**: Start the server with optimal settings

**⚠️ Troubleshooting Startup Scripts:**

If you encounter **NumPy compilation errors** on Windows:
```cmd
# Option 1: The script will try this automatically
pip install --upgrade pip wheel
pip install numpy --prefer-binary

# Option 2: Install Visual C++ Build Tools if needed
# Download from: https://visualstudio.microsoft.com/visual-cpp-build-tools/

# Option 3: Use conda if available
conda install numpy
```

If **SSL certificate errors** occur:
```bash
# The script creates self-signed certificates automatically
# Custom certificates can be placed as:
#   - dev.certificate.crt (certificate file)
#   - dev.private.key (private key file)
```

**🌐 After successful startup:**
- **Main Application**: `https://localhost:5001`
- **Admin Dashboard**: `https://localhost:5001/login`
  - Username: `AdminKitaBersama`
  - Password: `AdminKitaBersama`
- **Voting Page**: `https://localhost:5001/vote` (requires token)
- **Registration**: `https://localhost:5001/register_voter`

### Option 2: Manual Local Development Setup

*Use this option if you prefer manual control or the automated scripts don't work in your environment.*

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
pip install --upgrade pip wheel

# Install packages with fallback for compilation issues
pip install --prefer-binary -r requirements.txt

# If NumPy compilation fails on Windows, try:
pip install numpy --prefer-binary
pip install flask cryptography requests selenium beautifulsoup4 --prefer-binary
```

#### Step 4: Set Up Environment Configuration
```bash
# Environment variables are already configured in app.py
# Default settings work out-of-the-box for development
echo "✅ Configuration ready - using secure defaults"
```

#### Step 5: Initialize Database
```bash
# Create the database (if it doesn't exist)
python createdb.py

# Or the database will be created automatically on first run
```

#### Step 6: Generate SSL Certificates
```bash
# Generate self-signed SSL certificate for HTTPS
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 \
  -nodes -keyout dev.private.key -out dev.certificate.crt \
  -subj "/CN=Pemilihan Umum Taruna" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:0.0.0.0"

# On Windows PowerShell (if OpenSSL is not available):
# The application will create basic certificates automatically
```

#### Step 7: Run Application
```bash
# Start the Flask application
python app.py

# Or for development mode:
python main.py
```

**🌐 Access the application:**
- **Main application**: `https://localhost:5001`
- **Admin dashboard**: `https://localhost:5001/login`
  - Username: `AdminKitaBersama`
  - Password: `AdminKitaBersama`

**🔧 Manual Setup Troubleshooting:**

**Python version issues:**
```bash
# Check Python version (needs 3.8+)
python --version

# If using multiple Python versions:
python3 -m venv venv
python3 app.py
```

**Package installation errors:**
```bash
# For compile errors, use pre-built wheels:
pip install --only-binary=all -r requirements.txt

# Install individual packages if bulk install fails:
pip install flask
pip install cryptography --prefer-binary
pip install numpy --prefer-binary
```

**Port conflicts:**
```bash
# If port 5001 is busy, edit app.py and change:
app.run(host='0.0.0.0', port=5002, ssl_context='adhoc')
```

### Option 3: Docker Deployment

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

### Option 4: Production Deployment

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

### Development Setup

```bash
# For development with auto-reload
python app.py

# Or with Flask CLI
export FLASK_APP=app.py          # Linux/macOS
set FLASK_APP=app.py             # Windows
export FLASK_ENV=development     # Linux/macOS
set FLASK_ENV=development        # Windows
flask run --cert=dev.certificate.crt --key=dev.private.key --port=5001
```

### Test Data Generation

```bash
# Generate sample voters and votes
python generate_dummy_votes.py
```

## 🛠️ Troubleshooting Guide

### Common Installation Issues

#### **NumPy Compilation Errors on Windows**
```cmd
ERROR: Microsoft Visual C++ 14.0 is required
```
**Solutions:**
1. **Use Pre-compiled Packages (Fastest)**:
   ```cmd
   pip install --upgrade pip wheel
   pip install numpy --prefer-binary
   pip install -r requirements.txt --prefer-binary
   ```

2. **Install Visual C++ Build Tools**:
   - Download from: https://visualstudio.microsoft.com/visual-cpp-build-tools/
   - Install "C++ build tools" workload
   - Restart command prompt and retry

3. **Use Conda Alternative**:
   ```cmd
   conda install numpy flask cryptography
   ```

#### **SSL Certificate Issues**
```
SSL: CERTIFICATE_VERIFY_FAILED
```
**Solutions:**
1. **Generate Fresh Certificates**:
   ```bash
   # Delete old certificates
   del dev.certificate.crt dev.private.key  # Windows
   rm dev.certificate.crt dev.private.key   # Linux/macOS

   # Run startup script to regenerate
   start.bat        # Windows
   ./start.sh       # Linux/macOS
   ```

2. **Browser Security Warnings**:
   - Click "Advanced" → "Proceed to localhost (unsafe)"
   - This is normal for self-signed certificates in development

#### **Port Already in Use**
```
OSError: [Errno 48] Address already in use
```
**Solutions:**
1. **Find and Kill Process**:
   ```cmd
   # Windows
   netstat -ano | findstr :5001
   taskkill /PID <process_id> /F

   # Linux/macOS
   lsof -ti:5001 | xargs kill -9
   ```

2. **Use Different Port**:
   ```bash
   # Edit app.py, change line:
   app.run(host='0.0.0.0', port=5002, ssl_context='adhoc')
   ```

#### **Database Access Issues**
```
sqlite3.OperationalError: database is locked
```
**Solutions:**
1. **Reset Database**:
   ```bash
   # Delete and recreate database
   del evoting.db instance\evoting.db     # Windows
   rm evoting.db instance/evoting.db      # Linux/macOS

   python createdb.py
   ```

2. **Fix Permissions**:
   ```bash
   # Linux/macOS
   chmod 664 evoting.db
   chmod 775 instance/
   ```

### Browser-Specific Issues

#### **Chrome/Edge: NET::ERR_CERT_AUTHORITY_INVALID**
1. **Enable Unsafe Localhost**:
   - Navigate to: `chrome://flags/#allow-insecure-localhost`
   - Set to "Enabled"
   - Restart browser

2. **Accept Certificate**:
   - Click "Advanced" → "Proceed to localhost"

#### **Firefox: SEC_ERROR_UNKNOWN_ISSUER**
1. **Add Exception**:
   - Click "Advanced" → "Add Exception"
   - Click "Confirm Security Exception"

### Performance Issues

#### **Slow Startup or Response**
1. **Check System Resources**:
   ```bash
   # Monitor resource usage
   python benchmark_tabulasi.py
   ```

2. **Optimize for Development**:
   ```bash
   # Use debug mode for faster reload
   export FLASK_ENV=development  # Linux/macOS
   set FLASK_ENV=development     # Windows
   ```

### Docker-Specific Issues

#### **Docker Build Failures**
```bash
# Clear Docker cache and rebuild
docker system prune -a
docker-compose build --no-cache
```

#### **Container Won't Start**
```bash
# Check logs for errors
docker-compose logs app

# Check port conflicts
docker-compose ps
netstat -tulpn | grep :5001
```

### Development Environment Issues

#### **Import Errors**
```python
ModuleNotFoundError: No module named 'cryptomath'
```
**Solutions:**
1. **Verify Virtual Environment**:
   ```bash
   # Check if venv is activated
   which python  # Should show venv path

   # Reactivate if needed
   source venv/bin/activate  # Linux/macOS
   venv\Scripts\activate     # Windows
   ```

2. **Reinstall Dependencies**:
   ```bash
   pip install -r requirements.txt --force-reinstall
   ```

#### **Path Issues**
```python
FileNotFoundError: [Errno 2] No such file or directory
```
**Solutions:**
1. **Run from Correct Directory**:
   ```bash
   # Always run from project root
   cd Bismillah_TA
   python app.py
   ```

2. **Check File Structure**:
   ```bash
   # Verify files exist
   ls -la *.py        # Linux/macOS
   dir *.py           # Windows
   ```

### Getting Help

#### **Check System Status**
```bash
# Verify all components
python --version              # Should be 3.8+
pip --version                # Should be latest
python -c "import flask"      # Should not error
python -c "import cryptography"  # Should not error
```

#### **Enable Debug Mode**
```python
# In app.py, change:
app.run(host='0.0.0.0', port=5001, debug=True, ssl_context='adhoc')
```

#### **Generate System Report**
```bash
# Create troubleshooting report
echo "=== System Information ===" > debug_report.txt
python --version >> debug_report.txt
pip list >> debug_report.txt
echo "=== Directory Contents ===" >> debug_report.txt
ls -la >> debug_report.txt  # Linux/macOS
dir >> debug_report.txt     # Windows
```

**Still having issues?**
- Check the [GitHub Issues](https://github.com/RakhaMaulana/Bismillah_TA/issues)
- Create a new issue with your debug report

# Create initial database structure
python createdb.py
```

### 🔧 Troubleshooting

#### Common Issues and Solutions

**1. Script Permission Issues (Linux/macOS)**
```bash
# Make scripts executable
chmod +x start.sh
sudo chmod +x start.sh  # If permission denied
```

**2. Python Version Issues**
```bash
# Check Python version
python --version
python3 --version

# Use specific Python version
python3.11 -m venv venv  # Replace with your Python version
```

**3. SSL Certificate Issues**
```bash
# Generate new SSL certificates
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 \
  -nodes -keyout dev.private.key -out dev.certificate.crt \
  -subj "/CN=localhost"
```

**4. Port Already in Use**
```bash
# Check what's using port 5001
netstat -an | grep :5001  # Linux/macOS
netstat -an | findstr :5001  # Windows

# Kill process using the port
sudo kill -9 $(lsof -t -i:5001)  # Linux/macOS
# Or change port in app.py: app.run(port=5002)
```

**5. Database Issues**
```bash
# Reset database
rm -f evoting.db instance/evoting.db  # Linux/macOS
del evoting.db instance\evoting.db  # Windows

# Reinitialize database
python createdb.py
```

**6. Virtual Environment Issues**
```bash
# Remove and recreate virtual environment
rm -rf venv  # Linux/macOS
rmdir /s venv  # Windows

python -m venv venv
# Then run start script again
```

#### Script Arguments

**Windows (start.bat):**
```batch
start.bat          # Local deployment (default)
start.bat local    # Local deployment (explicit)
start.bat docker   # Docker deployment
```

**Linux/macOS (start.sh):**
```bash
./start.sh          # Local deployment (default)
./start.sh local    # Local deployment (explicit)
./start.sh docker   # Docker deployment
./start.sh --help   # Show help information
```

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


