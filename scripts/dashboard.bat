@echo off
REM Start the Threat2Signal dashboard (backend API + frontend dev server)
REM Usage: scripts\dashboard.bat
REM   --build    Serve production build instead of dev server

setlocal

set PROJECT_ROOT=%~dp0..
set PYTHON=%PROJECT_ROOT%\.venv\Scripts\python.exe
set NPM="C:\Program Files\nodejs\npm.cmd"

REM Verify Python venv
if not exist "%PYTHON%" (
    echo ERROR: Python venv not found. Run scripts\setup.bat first.
    exit /b 1
)

REM Verify node
where node >nul 2>&1
if errorlevel 1 (
    if not exist "C:\Program Files\nodejs\node.exe" (
        echo ERROR: Node.js not found. Install from https://nodejs.org
        exit /b 1
    )
)

REM Verify frontend dependencies
if not exist "%PROJECT_ROOT%\frontend\node_modules" (
    echo Installing frontend dependencies...
    pushd "%PROJECT_ROOT%\frontend"
    %NPM% install
    popd
)

REM Initialize database if needed
"%PYTHON%" -c "from threat2signal.storage.db import get_connection, init_schema; conn = get_connection('data/threat2signal.db'); init_schema(conn); conn.close()"

if "%1"=="--build" goto :production

REM === Development mode ===
echo Starting Threat2Signal Dashboard (dev mode)
echo   Backend:  http://127.0.0.1:8000
echo   Frontend: http://127.0.0.1:5173
echo.

REM Start backend in background
start "T2S-Backend" /min "%PYTHON%" -m uvicorn threat2signal.api:app --host 127.0.0.1 --port 8000

REM Wait for backend
timeout /t 2 /nobreak >nul

REM Start frontend dev server (foreground)
pushd "%PROJECT_ROOT%\frontend"
%NPM% run dev
popd

REM When frontend exits, kill backend
taskkill /fi "WINDOWTITLE eq T2S-Backend" >nul 2>&1
goto :eof

:production
REM === Production mode ===
echo Building frontend...
pushd "%PROJECT_ROOT%\frontend"
%NPM% run build
popd

echo Starting Threat2Signal Dashboard (production mode)
echo   Dashboard: http://127.0.0.1:8000
echo.

"%PYTHON%" -m uvicorn threat2signal.api:app --host 127.0.0.1 --port 8000
