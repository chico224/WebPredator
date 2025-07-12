@echo off
echo === Vérification de WebPredator ===
echo.

echo [1/3] Vérification des dossiers...
if exist config (
    echo   [OK] Dossier config existe
) else (
    echo   [ERREUR] Dossier config manquant
)

if exist logs (
    echo   [OK] Dossier logs existe
) else (
    echo   [ERREUR] Dossier logs manquant
)

if exist modules (
    echo   [OK] Dossier modules existe
) else (
    echo   [ERREUR] Dossier modules manquant
)

if exist reports (
    echo   [OK] Dossier reports existe
) else (
    echo   [ERREUR] Dossier reports manquant
)

echo.
echo [2/3] Vérification des fichiers...

if exist webpredator.sh (
    echo   [OK] Fichier webpredator.sh existe
) else (
    echo   [ERREUR] Fichier webpredator.sh manquant
)

if exist config\webpredator.conf (
    echo   [OK] Fichier config\webpredator.conf existe
) else (
    echo   [ERREUR] Fichier config\webpredator.conf manquant
)

if exist README.md (
    echo   [OK] Fichier README.md existe
) else (
    echo   [ERREUR] Fichier README.md manquant
)

if exist LICENSE (
    echo   [OK] Fichier LICENSE existe
) else (
    echo   [ERREUR] Fichier LICENSE manquant
)

echo.
echo [3/3] Vérification des dépendances...

echo   Python:
python --version 2>nul
if %errorlevel% neq 0 echo   [ERREUR] Python n'est pas installé

echo   Git:
git --version 2>nul
if %errorlevel% neq 0 echo   [ERREUR] Git n'est pas installé

echo.
echo === Prochaines étapes ===
echo 1. Installez les dépendances manquantes
echo 2. Pour utiliser WebPredator, vous avez besoin de :
echo    - WSL (Windows Subsystem for Linux) OU
echo    - Un environnement Linux/MacOS OU
echo    - Git Bash pour Windows
echo 3. Consultez le fichier README.md pour les instructions d'installation
echo.
pause
