@echo off
echo === Threat2Signal Setup ===

REM 1. Ensure all directories exist
if not exist "config" mkdir config
if not exist "data" mkdir data
if not exist "data\attack-stix" mkdir "data\attack-stix"
if not exist "data\assets" mkdir "data\assets"
if not exist "scripts" mkdir scripts
if not exist "templates\sigma" mkdir "templates\sigma"
if not exist "tests" mkdir tests

REM 2. Create venv if missing
if not exist ".venv\Scripts\python.exe" (
    echo Creating virtual environment...
    python -m venv .venv
)

REM 3. Upgrade pip
.venv\Scripts\python.exe -m pip install --upgrade pip

REM 4. Install dependencies
echo Installing dependencies...
.venv\Scripts\python.exe -m pip install -r requirements.txt

REM 5. Copy settings template if settings.yaml missing
if not exist "config\settings.yaml" (
    echo Copying settings template...
    copy config\settings.yaml.example config\settings.yaml
    echo.
    echo !!! Edit config\settings.yaml with your API keys before running the pipeline !!!
    echo.
)

REM 6. Initialize database
echo Initializing database...
.venv\Scripts\python.exe -m threat2signal.cli init-db

REM 7. Show status
echo.
echo === Setup complete ===
.venv\Scripts\python.exe -m threat2signal.cli status
