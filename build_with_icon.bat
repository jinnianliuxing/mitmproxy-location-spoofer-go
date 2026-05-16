@echo off
chcp 65001 >nul
title Build Go Launcher with Icon

cd /d "%~dp0"

echo ========================================
echo   Go Launcher - Build with Icon
echo ========================================
echo.

:: 检查Go是否安装
go version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Go is not installed or not in PATH
    echo Please install Go from https://golang.org/dl/
    pause
    exit /b 1
)

:: 检查图标文件是否存在
if not exist "app.ico" (
    echo [ERROR] app.ico not found!
    echo Please create an ICO file named "app.ico" in this directory
    echo.
    echo How to create app.ico:
    echo 1. Prepare any image (PNG, JPG recommended)
    echo 2. Convert to ICO format using online converter like:
    echo    - https://convertio.co/png-ico/
    echo    - https://icoconvert.com/
    echo 3. Save as "app.ico" in myproject folder
    echo 4. Re-run this script
    echo.
    pause
    exit /b 1
)

:: 清理旧的syso文件
if exist "*.syso" (
    del "*.syso"
)

:: 安装rsrc工具（如果未安装）
echo [*] Checking rsrc tool...
go install github.com/akavel/rsrc@latest >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Failed to install rsrc tool
    pause
    exit /b 1
)

:: 使用rsrc生成资源文件
echo [*] Generating icon resource file...
rsrc -ico app.ico -o app.syso

if errorlevel 1 (
    echo [ERROR] Failed to generate app.syso
    echo Make sure app.ico is a valid Windows ICO file
    pause
    exit /b 1
)

echo [OK] app.syso generated successfully

:: 清理旧的exe文件
if exist "Mitmproxy定位伪造工具.exe" (
    del "Mitmproxy定位伪造工具.exe"
)

:: 编译Go程序（注意：不能指定具体文件，要编译整个包）
echo [*] Compiling Go launcher with icon...
go build -ldflags "-s -w" -o "Mitmproxy定位伪造工具.exe" .

if errorlevel 1 (
    echo.
    echo [ERROR] Go compilation failed
    pause
    exit /b 1
)

:: 清理临时文件
if exist "*.syso" (
    del "*.syso"
)

echo.
echo ========================================
echo [OK] Build successful with icon!
echo ========================================
echo.
echo Output: Mitmproxy定位伪造工具.exe
echo Location: %~dp0
echo.
echo The executable now has your custom icon embedded!
echo You can copy it to the project root directory to replace
echo the existing executable.
echo.
pause