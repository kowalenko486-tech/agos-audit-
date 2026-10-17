@echo off
REM AGOS 4.1 Standalone External Validation Runner (Windows CMD)
chcp 65001 > nul
echo === [AGOS 4.1] Przygotowanie środowiska walidacyjnego Windows ===

if not exist venv (
    echo Tworzenie srodowiska venv...
    python -m venv venv
)

call venv\Scripts\activate.bat
echo Weryfikacja zaleznosci...
pip install -r requirements.txt -r requirements-test.txt

echo Uruchamianie pelnej walidacji Zero-Trust...
python run_validation.py %*
pause
