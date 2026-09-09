@echo off
chcp 65001 >nul
cd /d "%~dp0"
if not exist node_modules (
  echo === ติดตั้งครั้งแรก กรุณารอสักครู่ ===
  call npm install
)
echo === เริ่มระบบตารางงาน  http://localhost:3000 ===
node server.js
pause
