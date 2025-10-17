@echo off
REM Setup script for Compliance Guardian AI (Windows)

echo ==================================
echo Compliance Guardian AI - Setup
echo ==================================
echo.

REM Check Python version
echo Checking Python version...
python --version
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Python not found. Please install Python 3.11 or higher.
    exit /b 1
)

REM Create virtual environment
echo.
echo Creating virtual environment...
python -m venv venv

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat

REM Upgrade pip
echo.
echo Upgrading pip...
python -m pip install --upgrade pip

REM Install dependencies
echo.
echo Installing dependencies...
pip install -r requirements.txt

REM Create .env file if it doesn't exist
if not exist .env (
    echo.
    echo Creating .env file from template...
    copy .env.example .env
    echo Created .env file
    echo Please edit .env with your AWS credentials and configuration
) else (
    echo.
    echo .env file already exists
)

REM Create necessary directories
echo.
echo Creating output directories...
if not exist reports mkdir reports
if not exist exports mkdir exports
if not exist logs mkdir logs
echo Directories created

echo.
echo ==================================
echo Setup Complete!
echo ==================================
echo.
echo Next steps:
echo 1. Edit .env file with your AWS credentials
echo 2. Activate virtual environment: venv\Scripts\activate
echo 3. Start the API: python -m src.api.main
echo 4. Access docs at: http://localhost:8000/docs
echo.

pause
