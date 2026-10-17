# AGOS 4.1 Core — Samodzielna Paczka Walidacji Zewnętrznej (Standalone External Validator)

[![AGOS 4.1 External Security Validation](https://github.com/kowalenko486-tech/agos-audit-/actions/workflows/external_validation.yml/badge.svg)](https://github.com/kowalenko486-tech/agos-audit-/actions/workflows/external_validation.yml)
![Zero-Trust](https://img.shields.io/badge/Security-Zero--Trust%20Compliant-brightgreen)
![OWASP LLM](https://img.shields.io/badge/OWASP-Top%2010%20LLM%20Passed-blue)
![Exit Code](https://img.shields.io/badge/Exit%20Code-0%20(PASS)-success)

Ta paczka pozwala na **w pełni niezależną walidację bezpieczeństwa systemu AGOS 4.1 na dowolnej zewnętrznej maszynie**:
* **VPS / Serwer Linux (Ubuntu, Debian, AlmaLinux)**
* **Kontener Docker**
* **GitHub Actions / GitLab CI**
* **Inny komputer deweloperski (Windows / macOS / Linux)**

---

## 🚀 Jak uruchomić na zewnętrznej maszynie?

### Opcja 1: Jedną komendą w Dockerze (Dowolny system / Chmura)
Jeśli masz zainstalowanego Dockera:
```bash
docker build -t agos-val .
docker run --rm agos-val
```

---

### Opcja 2: Na serwerze Linux / VPS / macOS
```bash
chmod +x run_validation.sh
./run_validation.sh
```
*Skrypt automatycznie utworzy wirtualne środowisko `venv`, zainstaluje zależności i uruchomi pełny audyt.*

---

### Opcja 3: Na komputerze z systemem Windows
Wystarczy dwukrotnie kliknąć lub uruchomić w wierszu poleceń:
```cmd
run_validation.bat
```
lub w PowerShell:
```powershell
.\run_validation.ps1
```

---

### Opcja 4: Czysty Python (jeśli masz już środowisko)
```bash
pip install -r requirements.txt -r requirements-test.txt
python run_validation.py
```
Dodatkowe opcje:
* `python run_validation.py --probe` — uruchamia tylko 14 szybkich sond bezpieczeństwa w pamięci (czas: < 2 sekundy).
* `python run_validation.py --all` — uruchamia wszystkie testy jednostkowe, integracyjne i adwersaryjne.

---

## 🛡️ Co sprawdza ten walidator?

1. **Sondy Egress DLP & TokenVault:**
   * Matematyczne sumy kontrolne PESEL (modulo-10 + data w 5 stuleciach), NIP (modulo-11), kart płatniczych (Luhn) i IBAN (ISO mod-97).
   * Maskowanie danych wrażliwych i lokalną odwracalność w `TokenVault`.
   * Przechwytywanie prób obejścia przez kodowanie Base64 (*Decode-and-Scan*).
   * Bezwzględne wycięcie klucza `AGOS_PROVENANCE_SECRET` przed wysłaniem do LLM.

2. **AST-SAST & Anti-Slopsquatting:**
   * Skaner drzewa AST wykrywający: `eval()`, `exec()`, `subprocess(shell=True)`, niebezpieczną deserializację `pickle` oraz `yaml.load()` bez SafeLoader.
   * `DependencyGuard` wykrywający pakiety AI-halucynowane (*slopsquatting*) oraz literówki (*typosquatting*).

3. **Ochrona plików i granic projektu:**
   * Blokada dostępu do plików `.env`, certyfikatów, kluczy SSH i struktur Git.
   * Blokada ścieżek sieciowych UNC (`\\host\share`) oraz ucieczek z katalogu (`../../`).

4. **Policy Engine & Git Safety (R21–R40):**
   * Wykrywanie bezpośrednich prób modyfikacji plików z pominięciem procedury (`DIRECT_TOOL_BYPASS`).
   * Zabezpieczenie przed atakami na integralność planu, dowodów i zgód.
   * Zasada *Fail-Closed* przy jakimkolwiek błędzie wykonawczym.

---

## 📊 Wynik i Raport

Po zakończeniu działania skrypt generuje plik:
* `EXTERNAL_VALIDATION_RESULT.json` — maszynowo czytelny raport podsumowujący (czas, status, lista sond, kod wyjścia Pytest).
* Zwraca kod wyjścia `0` w przypadku 100% obrony lub `1` w razie naruszenia.
