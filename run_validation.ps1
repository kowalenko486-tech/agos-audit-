# AGOS 4.1 Standalone External Validation Runner (Windows PowerShell)
$ErrorActionPreference = "Stop"

Write-Host "=== [AGOS 4.1] Przygotowanie środowiska walidacyjnego PowerShell ===" -ForegroundColor Cyan

if (-not (Test-Path "venv")) {
    Write-Host "Tworzenie środowiska venv..." -ForegroundColor Yellow
    python -m venv venv
}

& "venv\Scripts\python.exe" -m pip install -r requirements.txt -r requirements-test.txt

Write-Host "`nUruchamianie pełnej walidacji Zero-Trust..." -ForegroundColor Green
& "venv\Scripts\python.exe" run_validation.py $args
