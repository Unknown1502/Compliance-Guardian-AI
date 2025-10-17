#!/bin/bash
# Setup script for Compliance Guardian AI

set -e

echo "=================================="
echo "Compliance Guardian AI - Setup"
echo "=================================="
echo ""

# Check Python version
echo "Checking Python version..."
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "Found Python $python_version"

if ! python3 -c 'import sys; exit(0 if sys.version_info >= (3, 11) else 1)'; then
    echo "ERROR: Python 3.11 or higher is required"
    exit 1
fi

# Create virtual environment
echo ""
echo "Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo ""
echo "Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo ""
echo "Installing dependencies..."
pip install -r requirements.txt

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo ""
    echo "Creating .env file from template..."
    cp .env.example .env
    echo "[OK] Created .env file"
    echo "[WARNING]  Please edit .env with your AWS credentials and configuration"
else
    echo ""
    echo "[OK] .env file already exists"
fi

# Create necessary directories
echo ""
echo "Creating output directories..."
mkdir -p reports
mkdir -p exports
mkdir -p logs
echo "[OK] Directories created"

# Run tests (optional)
read -p "Do you want to run tests? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "Running tests..."
    pytest tests/ -v
fi

echo ""
echo "=================================="
echo "Setup Complete!"
echo "=================================="
echo ""
echo "Next steps:"
echo "1. Edit .env file with your AWS credentials"
echo "2. Activate virtual environment: source venv/bin/activate"
echo "3. Start the API: python -m src.api.main"
echo "4. Access docs at: http://localhost:8000/docs"
echo ""
