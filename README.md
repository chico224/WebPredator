# WebPredator - Ultimate Web Security Framework

WebPredator est un framework complet d'audit de sécurité web qui intègre des fonctionnalités avancées de reconnaissance, d'analyse de vulnérabilités et de génération de rapports.

## Fonctionnalités

- **Reconnaissance** : WHOIS, DNS, sous-domaines
- **Analyse de sécurité** : Scan Nmap, analyse des en-têtes, tests de vulnérabilités
- **Analyse web** : Fingerprinting, recherche de répertoires, tests XSS/SQLi
- **Analyse d'API** : Détection d'endpoints, tests de sécurité
- **Analyse avancée** : Intégration avec Python, Perl, Java et Go
- **Rapports** : Génération de rapports en HTML, JSON, CSV et texte

## Prérequis

- Bash 4.0 ou supérieur
- Python 3.x
- Perl 5.x
- Java 8 ou supérieur
- Go 1.13 ou supérieur
- Outils système : curl, nmap, whatweb, dirb, etc.

## Installation

1. Clonez le dépôt :
   ```
   git clone https://github.com/votre-utilisateur/webpredator.git
   cd webpredator
   ```

2. Installez les dépendances :
   - Sur Debian/Ubuntu :
     ```
     sudo apt update && sudo apt install -y curl nmap python3 perl default-jdk golang git whatweb dirb
     ```
   - Sur RedHat/CentOS :
     ```
     sudo yum install -y curl nmap python3 perl java-11-openjdk golang git whatweb dirb
     ```

3. Rendez le script exécutable :
   ```
   chmod +x webpredator.sh
   ```

## Utilisation

```
./webpredator.sh [OPTIONS] -t TARGET
```

### Options principales

- `-t, --target TARGET`     Cible à analyser (URL ou adresse IP)
- `-s, --scan TYPE`         Type d'analyse : quick, basic (défaut), full
- `-o, --output FORMAT`     Format du rapport : html (défaut), json, csv, txt
- `-T, --threads NUM`       Nombre de threads parallèles (défaut: 10)
- `-d, --depth NUM`         Profondeur maximale de l'analyse (1-5, défaut: 2)
- `-v, --verbose`           Mode verbeux
- `-D, --debug`             Mode débogage
- `-h, --help`              Afficher l'aide

### Exemples

Analyse de base avec sortie HTML :
```
./webpredator.sh -t example.com
```

Analyse complète avec 20 threads :
```
./webpredator.sh -t example.com -s full -T 20
```

Générer un rapport JSON :
```
./webpredator.sh -t example.com -o json
```

## Structure des dossiers

- `config/` : Fichiers de configuration
- `logs/` : Fichiers de log
- `reports/` : Rapports générés
- `modules/` : Modules personnalisés (Python, Perl, Java, Go)

## Licence

Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.

## Avertissement

Cet outil est fourni uniquement à des fins éducatives et légales. L'utilisation de cet outil pour attaquer des cibles sans autorisation préalable est illégale. Les développeurs ne sont pas responsables de toute utilisation malveillante ou dommage causé par cet outil.
