Write-Host "=== Test de WebPredator ===" -ForegroundColor Cyan

# Vérifier la structure des dossiers
Write-Host "`n[1/4] Vérification de la structure des dossiers..." -ForegroundColor Yellow
$requiredDirs = @("config", "logs", "modules", "reports")
$allDirsExist = $true

foreach ($dir in $requiredDirs) {
    if (Test-Path -Path $dir) {
        Write-Host "  ✓ $dir existe" -ForegroundColor Green
    } else {
        Write-Host "  ✗ $dir manquant" -ForegroundColor Red
        $allDirsExist = $false
    }
}

# Vérifier les fichiers essentiels
Write-Host "`n[2/4] Vérification des fichiers essentiels..." -ForegroundColor Yellow
$requiredFiles = @("webpredator.sh", "config/webpredator.conf", "README.md", "LICENSE")
$allFilesExist = $true

foreach ($file in $requiredFiles) {
    if (Test-Path -Path $file) {
        Write-Host "  ✓ $file existe" -ForegroundColor Green
    } else {
        Write-Host "  ✗ $file manquant" -ForegroundColor Red
        $allFilesExist = $false
    }
}

# Vérifier le contenu du fichier de configuration
Write-Host "`n[3/4] Vérification du fichier de configuration..." -ForegroundColor Yellow
$configContent = Get-Content -Path "config/webpredator.conf" -ErrorAction SilentlyContinue

if ($configContent -match "DEFAULT_SCAN_TYPE") {
    Write-Host "  ✓ Le fichier de configuration semble valide" -ForegroundColor Green
} else {
    Write-Host "  ✗ Le fichier de configuration semble vide ou corrompu" -ForegroundColor Red
}

# Vérifier les dépendances logicielles
Write-Host "`n[4/4] Vérification des dépendances logicielles..." -ForegroundColor Yellow
$dependencies = @("python", "perl", "java", "go", "git")
$missingDeps = @()

foreach ($dep in $dependencies) {
    $installed = $false
    
    # Vérifier via where
    $whereCmd = Get-Command $dep -ErrorAction SilentlyContinue
    if ($whereCmd) {
        $version = & $dep --version 2>&1 | Select-Object -First 1
        Write-Host "  ✓ $dep trouvé: $version" -ForegroundColor Green
        $installed = $true
    }
    
    if (-not $installed) {
        Write-Host "  ✗ $dep non trouvé" -ForegroundColor Red
        $missingDeps += $dep
    }
}

# Afficher le résumé des tests
Write-Host "`n=== Résumé des tests ===" -ForegroundColor Cyan

if ($allDirsExist -and $allFilesExist -and $missingDeps.Count -eq 0) {
    Write-Host "✅ Tous les tests ont réussi!" -ForegroundColor Green
    Write-Host "Le framework est prêt à l'emploi." -ForegroundColor Green
} else {
    Write-Host "❌ Certains tests ont échoué:" -ForegroundColor Red
    
    if (-not $allDirsExist) {
        Write-Host "- Certains dossiers requis sont manquants" -ForegroundColor Red
    }
    
    if (-not $allFilesExist) {
        Write-Host "- Certains fichiers essentiels sont manquants" -ForegroundColor Red
    }
    
    if ($missingDeps.Count -gt 0) {
        Write-Host ("- Dépendances manquantes: " + ($missingDeps -join ", ")) -ForegroundColor Red
    }
    
    Write-Host "`nPour résoudre ces problèmes, consultez le fichier README.md pour les instructions d'installation." -ForegroundColor Yellow
}

# Afficher les prochaines étapes
Write-Host "`n=== Prochaines étapes ===" -ForegroundColor Cyan
Write-Host "1. Installez les dépendances manquantes listées ci-dessus"
Write-Host "2. Pour utiliser WebPredator, vous aurez besoin de :"
Write-Host "   - Installer WSL (Windows Subsystem for Linux)"
Write-Host "   - Ou utiliser un environnement Linux/MacOS"
Write-Host "   - Ou installer Git Bash pour Windows"
Write-Host "3. Consultez le fichier README.md pour plus d'informations"
