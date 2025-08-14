@echo off
REM E-Voting System Startup Script for Windows
REM Cross-platform deployment script

echo ========================================
echo    E-Voting System Deployment Script
echo ========================================

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

REM Install dependencies
echo [INFO] Installing dependencies...
if exist "config\requirements.txt" (
    pip install -r config\requirements.txt
) else if exist "requirements.txt" (
    pip install -r requirements.txt
) else (
    echo [ERROR] No requirements.txt found
    pause
    exit /b 1
)

if %errorlevel% neq 0 (
    echo [ERROR] Failed to install dependencies
    pause
    exit /b 1
)

echo [INFO] Dependencies installed successfully

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
if "%1"=="local" pause
exit /b 0
