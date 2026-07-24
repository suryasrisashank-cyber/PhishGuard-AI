# PhishGuard AI Pro - Complete Startup Script
# Run this script to start both backend and frontend servers

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "PhishGuard AI Pro - Complete Startup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$projectRoot = $PSScriptRoot
$python = "$projectRoot\.venv\Scripts\python.exe"

# Kill any existing processes on ports 8000 and 3000
Write-Host "`n[*] Cleaning up existing processes..." -ForegroundColor Yellow

$existingPort8000 = Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue
if ($existingPort8000) {
    $pid = $existingPort8000.OwningProcess
    Write-Host "    Killing existing process on port 8000 (PID $pid)" -ForegroundColor Gray
    Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
}

$existingPort3000 = Get-NetTCPConnection -LocalPort 3000 -ErrorAction SilentlyContinue
if ($existingPort3000) {
    $pid = $existingPort3000.OwningProcess
    Write-Host "    Killing existing process on port 3000 (PID $pid)" -ForegroundColor Gray
    Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
}

# Start Backend
Write-Host "`n[1/2] Starting FastAPI Backend..." -ForegroundColor Green
Push-Location $projectRoot
$backendProc = Start-Process -FilePath $python `
    -ArgumentList "-m", "uvicorn", "backend.app.main:app", "--host", "127.0.0.1", "--port", "8000", "--reload" `
    -NoNewWindow `
    -PassThru
Write-Host "    [+] Backend started (PID $($backendProc.Id))" -ForegroundColor Green
Start-Sleep -Seconds 5

# Start Frontend
Write-Host "`n[2/2] Starting React/Vite Frontend..." -ForegroundColor Green
Push-Location "$projectRoot\frontend"
$frontendProc = Start-Process -FilePath "npm" `
    -ArgumentList "run", "dev" `
    -NoNewWindow `
    -PassThru
Write-Host "    [+] Frontend started (PID $($frontendProc.Id))" -ForegroundColor Green
Start-Sleep -Seconds 5

Pop-Location

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "PhishGuard AI Pro is Running!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Frontend (React Vite):" -ForegroundColor White
Write-Host "  URL: http://127.0.0.1:3000" -ForegroundColor Cyan
Write-Host "  Open this in your browser" -ForegroundColor Gray
Write-Host ""
Write-Host "Backend (FastAPI):" -ForegroundColor White
Write-Host "  URL: http://127.0.0.1:8000" -ForegroundColor Cyan
Write-Host "  Docs: http://127.0.0.1:8000/docs" -ForegroundColor Gray
Write-Host ""
Write-Host "Processes:" -ForegroundColor White
Write-Host "  Backend (PID $($backendProc.Id)) - Press Ctrl+C in this terminal to stop" -ForegroundColor Gray
Write-Host "  Frontend (PID $($frontendProc.Id)) - Runs in separate window" -ForegroundColor Gray
Write-Host ""
Write-Host "Features Ready:" -ForegroundColor White
Write-Host "  - URL Scanning" -ForegroundColor Cyan
Write-Host "  - Website Analysis" -ForegroundColor Cyan
Write-Host "  - Dashboard with Live Stats" -ForegroundColor Cyan
Write-Host "  - Risk Gauge" -ForegroundColor Cyan
Write-Host "  - Charts (Pie & Bar)" -ForegroundColor Cyan
Write-Host "  - Recent Scans Table with Pagination" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press Ctrl+C in this terminal to stop all servers" -ForegroundColor Yellow

# Wait for Ctrl+C
try {
    while ($true) { Start-Sleep -Seconds 1 }
} finally {
    Write-Host "`n`n[*] Shutting down servers..." -ForegroundColor Yellow
    Stop-Process -Id $backendProc.Id -Force -ErrorAction SilentlyContinue
    Stop-Process -Id $frontendProc.Id -Force -ErrorAction SilentlyContinue
    Write-Host "[+] All servers stopped" -ForegroundColor Green
}
