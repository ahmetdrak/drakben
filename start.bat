title DRAKBEN Starter
color 0c
cls

echo ===================================================
echo     DRAKBEN - Autonomous Pentest Agent
echo ===================================================
echo.

:: Check for Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found! Please install Python 3.8+
    pause
    exit /b 1
)

:: Check for Virtual Env
if not exist .venv (
    echo [*] Creating virtual environment...
    python -m venv .venv
)

:: Activate Virtual Env
call .venv\Scripts\activate.bat

:: Install Requirements
echo [*] Checking dependencies...
pip install -r requirements.txt >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] Failed to install all dependencies. Trying to continue...
)

:: Run Drakben
echo.
echo [*] Starting DRAKBEN...
echo.
python drakben.py

pause
