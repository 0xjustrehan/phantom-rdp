@echo off
setlocal
echo [*] Building phantom-rdp release binary...
cargo build --release
if %ERRORLEVEL% EQU 0 (
    echo [+] Build successful: target\release\phantom-rdp.exe
    copy /Y target\release\phantom-rdp.exe phantom-rdp.exe >nul
    echo [+] Created standalone binary: phantom-rdp.exe
) else (
    echo [-] Build failed.
)
