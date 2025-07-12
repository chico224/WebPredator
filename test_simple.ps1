Write-Host "=== Test de WebPredator ===" -ForegroundColor Cyan

# Vérifier la structure des dossiers
Write-Host "`n[1/3] Vérification de la structure des dossiers..." -ForegroundColor Yellow
$requiredDirs = @("config", "logs", "modules", "reports")

foreach ($dir in $requiredDirs) {
    if (Test-Path -Path $dir) {
        Write-Host "  ✓ $dir existe" -ForegroundColor Green
    } else {
        Write-Host "  ✗ $dir manquant" -ForegroundColor Red
    }
}

# Vérifier les fichiers essentiels
Write-Host "`n[2/3] Vérification des fichiers essentiels..." -ForegroundColor Yellow
$requiredFiles = @("webpredator.sh", "config/webpredator.conf", "README.md", "LICENSE")

foreach ($file in $requiredFiles) {
    if (Test-Path -Path $file) {
        Write-Host "  ✓ $file existe" -ForegroundColor Green
    } else {
        Write-Host "  ✗ $file manquant" -ForegroundColor Red
    }
}

# Vérifier les dépendances logicielles de base
Write-Host "`n[3/3] Vérification des dépendances de base..." -ForegroundColor Yellow
$dependencies = @("python", "git")

foreach ($dep in $dependencies) {
    $installed = $false
    
    try {
        $version = & $dep --version 2>&1 | Select-Object -First 1
        if ($version) {
            Write-Host "  ✓ $dep trouvé: $version" -ForegroundColor Green
            $installed = $true
        }
    } catch {
        # Ignorer les erreurs
    }
    
    if (-not $installed) {
        Write-Host "  ✗ $dep non trouvé" -ForegroundColor Red
    }
}

# Afficher les prochaines étapes
Write-Host "`n=== Prochaines étapes ===" -ForegroundColor Cyan
Write-Host "1. Installez les dépendances manquantes"
Write-Host "2. Pour utiliser WebPredator, vous avez besoin de :"
Write-Host "   - WSL (Windows Subsystem for Linux) OU"
Write-Host "   - Un environnement Linux/MacOS OU"
Write-Host "   - Git Bash pour Windows"
Write-Host "3. Consultez le fichier README.md pour les instructions d'installation"
