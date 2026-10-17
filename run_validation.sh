#!/usr/bin/env bash
# AGOS 4.1 Standalone External Validation Runner (Linux / macOS / VPS / CI)
set -e

echo "=== [AGOS 4.1] Przygotowanie środowiska walidacyjnego ==="

# 1. Tworzenie i aktywacja wirtualnego środowiska jeśli nie istnieje
if [ ! -d "venv" ]; then
    echo "Tworzenie środowiska venv..."
    python3 -m venv venv
fi

source venv/bin/activate

# 2. Instalacja zależności
echo "Weryfikacja zależności..."
pip install --upgrade pip > /dev/null 2>&1
pip install -r requirements.txt -r requirements-test.txt

# 3. Uruchomienie walidatora
echo "Uruchamianie pełnej walidacji Zero-Trust..."
python run_validation.py "$@"
