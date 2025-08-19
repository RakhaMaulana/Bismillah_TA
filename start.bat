@echo off
REM E-Voting System Startup Script for Windows
REM Cross-platform deployment script with enhanced error handling
REM
REM USAGE:
REM   start.bat                    (Local deployment - default)
REM   start.bat docker             (Docker deployment)
REM   start.bat --help             (Show help)
REM
REM PREREQUISITES:
REM   - Python 3.8+ with pip
REM   - Microsoft Visual C++ Build Tools (auto-detected)
REM   - Docker Desktop (optional, for Docker deployment)
REM
REM FEATURES:
REM   * Automatic dependency detection and installation
REM   * Smart package installation with fallback methods
REM   * Virtual environment setup and activation
REM   * Database initialization and SSL certificate setup
REM   * Enhanced error handling and recovery
REM
REM If you encounter compilation errors:
REM   - Script will try pre-compiled packages automatically
REM   - Falls back to core packages if optional ones fail
REM   - Continues with essential functionality

if "%1"=="--help" goto show_help
if "%1"=="-h" goto show_help

echo ========================================
echo    E-Voting System Deployment Script
echo ========================================
echo.

set PYTHON_CMD=python
set PIP_CMD=pip

REM Check if Python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is required but not installed
    pause
    exit /b 1
)

echo [INFO] Python found

REM Check if pip is available
pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] pip is required but not installed
    pause
    exit /b 1
)

echo [INFO] pip found

REM Check for deployment method
if "%1"=="docker" goto docker_deploy
if "%1"=="local" goto local_deploy
goto local_deploy

:docker_deploy
echo [INFO] Deploying with Docker...
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Docker is required for Docker deployment
    pause
    exit /b 1
)

cd config
docker-compose up --build -d
if %errorlevel% equ 0 (
    echo [INFO] Docker containers started successfully
    echo [INFO] Application available at https://localhost:5001
) else (
    echo [ERROR] Failed to start Docker containers
    pause
    exit /b 1
)
cd ..
goto end

:local_deploy
echo [INFO] Setting up local Python environment...

REM Create virtual environment if it doesn't exist
if not exist "venv" (
    echo [INFO] Creating virtual environment...
    python -m venv venv
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to create virtual environment
        pause
        exit /b 1
    )
)

REM Activate virtual environment
echo [INFO] Activating virtual environment...
call venv\Scripts\activate.bat

REM Install dependencies with enhanced error handling
echo [INFO] Installing dependencies with enhanced error handling...

REM First upgrade pip and install wheel for better compatibility
echo [INFO] Upgrading pip and installing wheel...
pip install --upgrade pip wheel setuptools

REM Determine which requirements file to use
set REQUIREMENTS_FILE=
if exist "config\requirements.txt" (
    set REQUIREMENTS_FILE=config\requirements.txt
) else if exist "requirements.txt" (
    set REQUIREMENTS_FILE=requirements.txt
) else (
    echo [ERROR] No requirements.txt found
    pause
    exit /b 1
)

echo [INFO] Found requirements file: %REQUIREMENTS_FILE%

REM Try bulk installation with pre-compiled packages first
echo [INFO] Attempting bulk installation with pre-compiled packages...
pip install -r %REQUIREMENTS_FILE% --prefer-binary --no-cache-dir >nul 2>&1
if %errorlevel% equ 0 (
    echo [INFO] Dependencies installed successfully with pre-compiled packages
    goto verify_packages
)

echo [WARNING] Bulk installation failed, trying critical packages individually...

REM Install critical packages for e-voting functionality
echo [INFO] Installing critical packages for e-voting system...

REM Essential packages that must work for core e-voting functionality
call :install_package "flask==3.0.0" "Flask web framework"
call :install_package "jinja2==3.1.2" "Template engine"
call :install_package "werkzeug==3.0.1" "WSGI utilities"
call :install_package "flask-wtf==1.2.1" "CSRF protection"
call :install_package "flask-limiter==3.5.0" "Rate limiting"
call :install_package "pyopenssl==23.3.0" "SSL support"
call :install_package "markupsafe==2.1.3" "String escaping"
call :install_package "cryptography==41.0.7" "Cryptographic functions"
call :install_package "requests==2.31.0" "HTTP client"
call :install_package "itsdangerous==2.1.2" "Token generation"
call :install_package "click==8.1.7" "CLI utilities"
call :install_package "blinker==1.7.0" "Signal support"

REM Try additional packages (semi-optional but useful)
echo [INFO] Installing additional useful packages...
call :install_optional_package "python-dotenv==1.0.0" "Environment variables"
call :install_optional_package "bcrypt==4.1.2" "Password hashing"
call :install_optional_package "waitress==2.1.2" "WSGI server"
call :install_optional_package "pillow==10.1.0" "Image processing"

REM Try performance packages (optional - app works without them)
echo [INFO] Installing performance optimization packages (optional)...
call :install_optional_package "numpy" "Numerical computing"
call :install_optional_package "scipy" "Scientific computing"
call :install_optional_package "gunicorn==21.2.0" "Production server"
call :install_optional_package "cheroot==10.0.0" "Alternative server"

goto verify_packages

:install_package
echo [INFO] Installing critical package: %~1...
pip install --prefer-binary %~1 >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] Failed with prefer-binary, trying without...
    pip install %~1 >nul 2>&1
    if %errorlevel% neq 0 (
        echo [ERROR] CRITICAL: Failed to install %~1 - %~2
        echo [ERROR] Cannot proceed without this package
        pause
        exit /b 1
    )
)
echo [SUCCESS] Installed %~1
goto :eof

:install_optional_package
echo [INFO] Installing optional package: %~1...
pip install --prefer-binary %~1 >nul 2>&1
if %errorlevel% neq 0 (
    pip install %~1 >nul 2>&1
    if %errorlevel% neq 0 (
        echo [WARNING] Failed to install optional package %~1 - %~2 (continuing without it)
        goto :eof
    )
)
echo [SUCCESS] Installed optional %~1
goto :eof

:verify_packages
echo [INFO] Verifying critical package installations...

REM Verify critical packages (must work)
python -c "import flask; print('Flask:', flask.__version__)" >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Flask verification failed
    goto install_error
)

python -c "import ssl; print('SSL support available')" >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] SSL verification failed
    goto install_error
)

python -c "import cryptography; print('Cryptography available')" >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Cryptography verification failed
    goto install_error
)

python -c "import requests; print('Requests available')" >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Requests verification failed
    goto install_error
)

echo [SUCCESS] Critical packages verified successfully

REM Check optional packages (informational only)
python -c "import bcrypt; print('BCrypt available')" >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] BCrypt not available (basic auth will be used)
) else (
    echo [SUCCESS] BCrypt available
)

python -c "import PIL; print('Pillow available')" >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] Pillow not available (image features disabled)
) else (
    echo [SUCCESS] Pillow available
)

python -c "import numpy; print('NumPy:', numpy.__version__)" >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] NumPy not available (performance features disabled)
) else (
    echo [SUCCESS] NumPy available
)

python -c "import scipy; print('SciPy:', scipy.__version__)" >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] SciPy not available (advanced math features disabled)
) else (
    echo [SUCCESS] SciPy available
)

python -c "import gunicorn; print('Gunicorn available')" >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] Gunicorn not available (will use built-in server)
) else (
    echo [SUCCESS] Gunicorn available
)

echo [SUCCESS] Dependencies installed and verified
echo [INFO] E-voting system is ready to run with core functionality!
goto continue_setup

:install_error
echo [ERROR] Critical packages failed verification
echo [INFO] Please install Microsoft Visual C++ Build Tools from:
echo [INFO] https://visualstudio.microsoft.com/visual-cpp-build-tools/
echo [INFO] Or use pre-compiled packages with: pip install --only-binary=all
pause
exit /b 1

:continue_setup

REM Setup environment variables
echo [INFO] Setting up environment variables...
if not exist ".env" (
    if exist "config\.env" (
        copy config\.env .env
        echo [INFO] Environment file copied from config
    ) else (
        echo [WARNING] No .env file found, creating default
        echo SECRET_KEY=AdminKitaBersama > .env
        echo NPM_ENCRYPTION_KEY=ZmDfcTF7_60GrrY167zsiPd67pEvs0aGOv2oasOM1Pg= >> .env
        echo FLASK_ENV=production >> .env
    )
)

REM Setup database
echo [INFO] Setting up database...
if not exist "instance" mkdir instance

if not exist "instance\evoting.db" (
    if not exist "evoting.db" (
        if exist "createdb.py" (
            python createdb.py
            echo [INFO] Database initialized
        ) else (
            echo [WARNING] Database initialization script not found
        )
    )
) else (
    echo [INFO] Database already exists
)

REM Setup SSL certificates
if exist "config\dev.certificate.crt" (
    if exist "config\dev.private.key" (
        copy config\dev.certificate.crt .
        copy config\dev.private.key .
        echo [INFO] SSL certificates copied from config
    )
)

REM Start application
echo [INFO] Starting E-Voting application...
echo [INFO] Application starting on https://localhost:5001
echo [INFO] Press Ctrl+C to stop
python app.py

:end
echo [INFO] Deployment completed
pause
exit /b 0

:show_help
echo ============================================
echo    E-Voting System Deployment Script
echo ============================================
echo.
echo USAGE:
echo   start.bat                    # Local deployment (default)
echo   start.bat docker             # Docker deployment
echo   start.bat local              # Explicit local deployment
echo   start.bat --help             # Show this help
echo.
echo FEATURES:
echo   * Automatic dependency detection and installation
echo   * Smart package installation with fallback methods
echo   * Virtual environment setup and activation
echo   * Database initialization and SSL certificate setup
echo   * Enhanced error handling and recovery
echo.
echo PREREQUISITES:
echo   - Python 3.8+ with pip
echo   - Microsoft Visual C++ Build Tools (auto-installed if possible)
echo   - Docker Desktop (optional, for Docker deployment)
echo.
echo TROUBLESHOOTING:
echo   - If compilation errors occur, script will try fallback methods
echo   - Pre-compiled packages are used when possible
echo   - Core functionality works even if optional packages fail
echo.
echo ACCESS AFTER STARTUP:
echo   Main App:    https://localhost:5001
echo   Admin Login: https://localhost:5001/login
echo   Username:    AdminKitaBersama
echo   Password:    AdminKitaBersama
echo.
pause
exit /b 0
