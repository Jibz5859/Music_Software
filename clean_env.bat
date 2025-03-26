@echo off
:: Clean Reset Script for Python Virtual Environment
:: ----------------------------------------------

echo Step 1/4: Deactivating current virtual environment...
call deactivate 2>nul

echo Step 2/4: Removing old virtual environment...
rmdir /s /q venv 2>nul

echo Step 3/4: Creating fresh virtual environment...
python -m venv venv
if errorlevel 1 (
    echo Failed to create virtual environment
    pause
    exit /b 1
)

echo Step 4/4: Installing required packages...
call venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt

echo.
echo ----------------------------------------------
echo Environment has been completely reset!
echo Installed packages:
pip list
echo ----------------------------------------------
pause