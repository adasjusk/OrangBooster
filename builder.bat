@echo off
setlocal
set VENV_DIR=%~dp0venv
set PYTHON_EXE=%VENV_DIR%\Scripts\python.exe
set PIP_EXE=%VENV_DIR%\Scripts\pip.exe

if not exist "%VENV_DIR%" (
    echo Creating virtual environment...
    python -m venv "%VENV_DIR%"
)
if exist "%PIP_EXE%" (
    echo Installing requirements...
    "%PIP_EXE%" install --upgrade pip
    "%PIP_EXE%" install requests Pillow opencv-python packaging psutil customtkinter pyinstaller
) else (
    echo ERROR: pip not found in venv!
    exit /b 1
)
"%PYTHON_EXE%" -m PyInstaller --noconfirm --onefile --windowed --icon "C:\ProgramData\InterJava-Programs\orange.ico" --name "orangbostr" --clean --uac-admin  "%~dp0main.py"

if %errorlevel%==0 (
    echo Build complete! Check the dist folder for orangbostr.exe
) else (
    echo Build failed!
    goto cleanup
)

:cleanup
rmdir /s /q "%VENV_DIR%"
rmdir /s /q "%~dp0build"
del /f /q "%~dp0orangbostr.spec"
if exist "%~dp0dist" (
    ren "%~dp0dist" build
)
pause
endlocal