#!/bin/bash

# E-Voting System Startup Script
# Cross-platform deployment script

set -e  # Exit on error

echo "🚀 Starting E-Voting System Deployment..."

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running on Windows (Git Bash, WSL, etc.)
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" || "$OSTYPE" == "cygwin" ]]; then
    PLATFORM="windows"
    print_status "Detected Windows platform"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    PLATFORM="linux"
    print_status "Detected Linux platform"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    PLATFORM="macos"
    print_status "Detected macOS platform"
else
    PLATFORM="unknown"
    print_warning "Unknown platform detected, proceeding with Linux defaults"
fi

# Check dependencies
check_dependencies() {
    print_status "Checking dependencies..."

    # Check Python
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
        print_status "Python $PYTHON_VERSION found"
    else
        print_error "Python 3 is required but not installed"
        exit 1
    fi

    # Check pip
    if command -v pip3 &> /dev/null || command -v pip &> /dev/null; then
        print_status "pip found"
    else
        print_error "pip is required but not installed"
        exit 1
    fi

    # Check Docker (optional)
    if command -v docker &> /dev/null; then
        print_status "Docker found"
        DOCKER_AVAILABLE=true
    else
        print_warning "Docker not found - will use local Python environment"
        DOCKER_AVAILABLE=false
    fi
}

# Setup virtual environment
setup_venv() {
    print_status "Setting up Python virtual environment..."

    if [ ! -d "venv" ]; then
        python3 -m venv venv
        print_status "Virtual environment created"
    fi

    # Activate virtual environment
    if [[ "$PLATFORM" == "windows" ]]; then
        source venv/Scripts/activate
    else
        source venv/bin/activate
    fi

    print_status "Virtual environment activated"
}

# Install dependencies
install_dependencies() {
    print_status "Installing Python dependencies..."

    if [ -f "config/requirements.txt" ]; then
        pip install -r config/requirements.txt
    elif [ -f "requirements.txt" ]; then
        pip install -r requirements.txt
    else
        print_error "No requirements.txt found"
        exit 1
    fi

    print_status "Dependencies installed successfully"
}

# Setup database
setup_database() {
    print_status "Setting up database..."

    # Create instance directory if it doesn't exist
    mkdir -p instance

    # Initialize database if it doesn't exist
    if [ ! -f "instance/evoting.db" ] && [ ! -f "evoting.db" ]; then
        if [ -f "createdb.py" ]; then
            python createdb.py
            print_status "Database initialized"
        else
            print_warning "Database initialization script not found"
        fi
    else
        print_status "Database already exists"
    fi
}

# Setup environment variables
setup_environment() {
    print_status "Setting up environment variables..."

    if [ ! -f ".env" ] && [ -f "config/.env" ]; then
        cp config/.env .env
        print_status "Environment file copied from config"
    elif [ ! -f ".env" ]; then
        print_warning "No .env file found, using defaults"
        cat > .env << EOF
SECRET_KEY=AdminKitaBersama
NPM_ENCRYPTION_KEY=ZmDfcTF7_60GrrY167zsiPd67pEvs0aGOv2oasOM1Pg=
FLASK_ENV=production
EOF
    fi
}

# Start application
start_application() {
    print_status "Starting E-Voting application..."

    # Check if certificates exist
    if [ -f "dev.certificate.crt" ] && [ -f "dev.private.key" ]; then
        print_status "SSL certificates found"
    elif [ -f "config/dev.certificate.crt" ] && [ -f "config/dev.private.key" ]; then
        print_status "SSL certificates found in config directory"
        cp config/dev.certificate.crt .
        cp config/dev.private.key .
    else
        print_warning "SSL certificates not found - application may not start properly"
    fi

    # Start the application
    print_status "🎯 Application starting on https://localhost:5001"
    print_status "Press Ctrl+C to stop"

    python app.py
}

# Docker deployment option
deploy_docker() {
    print_status "Deploying with Docker..."

    if [ -f "config/docker-compose.yml" ]; then
        cd config
        docker-compose up --build -d
        cd ..
        print_status "Docker containers started successfully"
        print_status "Application available at https://localhost:5001"
    else
        print_error "docker-compose.yml not found in config directory"
        exit 1
    fi
}

# Main execution
main() {
    echo "============================================"
    echo "    E-Voting System Deployment Script"
    echo "============================================"

    check_dependencies

    # Check for deployment method preference
    if [[ "$1" == "docker" ]] && [[ "$DOCKER_AVAILABLE" == true ]]; then
        deploy_docker
    else
        setup_venv
        install_dependencies
        setup_environment
        setup_database
        start_application
    fi
}

# Handle script arguments
case "$1" in
    "docker")
        main docker
        ;;
    "local")
        main local
        ;;
    "--help"|"-h")
        echo "Usage: $0 [docker|local]"
        echo "  docker: Deploy using Docker containers"
        echo "  local:  Deploy using local Python environment (default)"
        exit 0
        ;;
    *)
        main local
        ;;
esac
