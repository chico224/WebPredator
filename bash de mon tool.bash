#!/bin/bash

# ================================================
# WebPredator - Ultimate Web Penetration Testing Framework
# Version: 2.0.0
# Author: Chico
# License: MIT
# ================================================

# Configuration
VERSION="2.0.0"
AUTHOR="Chico"
CONFIG_FILE="webpredator.conf"
LOG_DIR="logs"
REPORTS_DIR="reports"
TEMP_DIR="/tmp/webpredator_$(date +%s)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'
UNDERLINE='\033[4m'

# Default values
TARGET=""
OUTPUT_FORMAT="html"
THREADS=10
VERBOSE=0
DEBUG=0
SCAN_TYPE="basic"
USER_AGENT="WebPredator/$VERSION"
TIMEOUT=30
DEPTH=2

# Dependencies
REQUIRED_TOOLS=(
    ["curl"]="Transfert de données URL (https://curl.se/)"
    ["nmap"]="Découverte de réseau et d'audit de sécurité (https://nmap.org/)"
    ["whatweb"]="Empreinte de serveur web (https://github.com/urbanadventurer/WhatWeb)"
    ["dirb"]="Recherche de répertoires web (https://tools.kali.org/web-applications/dirb)"
    ["nikto"]="Scanner de vulnérabilités web (https://cirt.net/nikto2)"
    ["sqlmap"]="Détection et exploitation d'injections SQL (https://sqlmap.org/)"
    ["gobuster"]="Brute force de dossiers/fichiers (https://github.com/OJ/gobuster)"
    ["subfinder"]="Découverte de sous-domaines (https://github.com/projectdiscovery/subfinder)"
    ["httprobe"]="Vérification des domaines actifs (https://github.com/tomnomnom/httprobe)"
    ["waybackurls"]="Extraction des URLs historiques (https://github.com/tomnomnom/waybackurls)"
    ["dnsrecon"]="Énumération DNS (https://github.com/darkoperator/dnsrecon)"
)

# ================================================
# Utility Functions
# ================================================

show_banner() {
    clear
    echo -e "${RED}"
    cat << "EOF"
██╗    ██╗███████╗██████╗ ██████╗ ██████╗ ███████╗██████╗ ███████╗████████╗ █████╗ ██████╗ 
██║    ██║██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██╔══██╗
██║ █╗ ██║█████╗  ██████╔╝██████╔╝██████╔╝█████╗  ██████╔╝█████╗     ██║   ███████║██║  ██║
██║███╗██║██╔══╝  ██╔══██╗██╔═══╝ ██╔═══╝ ██╔══╝  ██╔══██╗██╔══╝     ██║   ██╔══██║██║  ██║
╚███╔███╔╝███████╗██║  ██║██║     ██║     ███████╗██║  ██║███████╗   ██║   ██║  ██║██████╔╝
 ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═════╝ 
EOF
    echo -e "${YELLOW}                  WebPredator – Ultimate Web Penetration Testing Framework"
    echo -e "${BLUE}                           Recon • Scan • Exploit • Report"
    echo -e "${GREEN}                         Version: $VERSION | Created by ${BOLD}${AUTHOR}${NC}\n"
}

show_webpredator_banner() {
    echo -e "${BOLD}${BLUE}»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»${NC}"
    echo -e "${BOLD}${GREEN}     WebPredator - Ultimate Web Security Tool     ${NC}"
    echo -e "${BOLD}${BLUE}»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»${NC}\n"
}

show_help() {
    show_webpredator_banner
    
    echo -e "${BOLD}${YELLOW}DESCRIPTION${NC}"
    echo -e "  WebPredator est un outil avancé d'audit de sécurité web offrant des fonctionnalités complètes"
    echo -e "  de reconnaissance, d'analyse de vulnérabilités et de génération de rapports.\n"
    
    echo -e "${BOLD}${YELLOW}UTILISATION${NC}"
    echo -e "  ${BOLD}$0 [OPTIONS] -t TARGET${NC}\n"
    
    echo -e "${BOLD}${YELLOW}OPTIONS OBLIGATOIRES${NC}"
    echo -e "  ${BOLD}-t, --target TARGET${NC}     Cible à analyser (URL ou adresse IP)\n"
    
    echo -e "${BOLD}${YELLOW}OPTIONS D'ANALYSE${NC}"
    echo -e "  ${BOLD}-s, --scan TYPE${NC}         Type d'analyse :"
    echo -e "                       quick: Analyse rapide (nmap basique, pas de scans intrusifs)"
    echo -e "                       basic: Analyse standard (nmap, whatweb, dirb) [défaut]"
    echo -e "                       full:  Analyse complète (inclut nikto et sqlmap)\n"
    echo -e "  ${BOLD}-d, --depth NUM${NC}         Profondeur maximale de l'analyse (1-5) [défaut: 2]\n"
    echo -e "  ${BOLD}-T, --threads NUM${NC}       Nombre de threads parallèles [défaut: 10]\n"
    
    echo -e "${BOLD}${YELLOW}OPTIONS DE SORTIE${NC}"
    echo -e "  ${BOLD}-o, --output FORMAT${NC}     Format du rapport :"
    echo -e "                       html:  Rapport HTML complet avec mise en forme [défaut]"
    echo -e "                       json:  Sortie structurée en JSON"
    echo -e "                       csv:   Format CSV pour tableurs"
    echo -e "                       txt:   Format texte simple\n"
    
    echo -e "  ${BOLD}-c, --config FILE${NC}       Fichier de configuration [défaut: webpredator.conf]\n"
    
    echo -e "${BOLD}${YELLOW}OPTIONS AVANCÉES${NC}"
    echo -e "  ${BOLD}-u, --user-agent STRING${NC} Définir un User-Agent personnalisé\n"
    echo -e "  ${BOLD}--proxy URL${NC}             Utiliser un proxy (ex: http://127.0.0.1:8080)\n"
    echo -e "  ${BOLD}--timeout SECONDS${NC}       Délai d'attente pour les requêtes [défaut: 30]\n"
    
    echo -e "${BOLD}${YELLOW}OPTIONS DE DÉBOGAGE${NC}"
    echo -e "  ${BOLD}-v, --verbose${NC}           Afficher plus de détails pendant l'exécution"
    echo -e "  ${BOLD}-D, --debug${NC}             Activer le mode débogage (très verbeux)\n"
    
    echo -e "${BOLD}${YELLOW}EXEMPLES D'UTILISATION${NC}"
    echo -e "  ${BOLD}Analyse de base avec sortie HTML :${NC}"
    echo -e "  $0 -t example.com\n"
    
    echo -e "  ${BOLD}Analyse complète avec 20 threads :${NC}"
    echo -e "  $0 -t example.com -s full -T 20\n"
    
    echo -e "  ${BOLD}Analyse avec proxy personnalisé :${NC}"
    echo -e "  $0 -t example.com --proxy http://localhost:8080\n"
    
    echo -e "  ${BOLD}Générer un rapport JSON :${NC}"
    echo -e "  $0 -t example.com -o json\n"
    
    echo -e "${BOLD}${YELLOW}NOTES${NC}"
    echo -e "  • Certaines fonctionnalités nécessitent des privilèges root"
    echo -e "  • L'outil est fourni uniquement à des fins éducatives et légales"
    echo -e "  • Obtenez une autorisation écrite avant d'analyser des systèmes qui ne vous appartiennent pas\n"
    
    echo -e "${BOLD}${GREEN}WebPredator v$VERSION - $AUTHOR - Pour usage éducatif uniquement${NC}\n"
    exit 0
}

check_dependencies() {
    local missing=0
    local total_tools=${#REQUIRED_TOOLS[@]}
    local found_tools=0
    
    echo -e "${BLUE}[*]${NC} Vérification des dépendances requises...\n"
    
    # Afficher l'en-tête du tableau
    printf "${BOLD}%-20s %-50s %-10s${NC}\n" "Outil" "Description" "Statut"
    echo -e "${BOLD}────────────────────────────────────────────────────────────────────────────${NC}"
    
    # Vérifier chaque outil
    for tool in "${!REQUIRED_TOOLS[@]}"; do
        local description="${REQUIRED_TOOLS[$tool]}"
        
        if command -v "$tool" &> /dev/null; then
            printf "${GREEN}%-20s %-50s %-10s${NC}\n" "$tool" "$description" "[OK]"
            found_tools=$((found_tools + 1))
        else
            printf "${RED}%-20s %-50s %-10s${NC}\n" "$tool" "$description" "[MANQUANT]"
            missing=$((missing + 1))
        fi
    done
    
    # Afficher le résumé
    echo -e "\n${BOLD}Résumé des dépendances :${NC}"
    echo -e "${GREEN}✓ $found_tools/$total_tools outils trouvés${NC}"
    
    if [ $missing -gt 0 ]; then
        echo -e "${RED}✗ $missing outils manquants${NC}"
        echo -e "\n${YELLOW}Pour installer les dépendances manquantes, exécutez :${NC}"
        echo -e "  # Sur Kali/Debian/Ubuntu :"
        echo -e "  sudo apt update && sudo apt install -y ${!REQUIRED_TOOLS[@]}"
        echo -e "\n  # Pour les outils non disponibles via apt :"
        echo -e "  # - whatweb, nikto, dirb : sudo apt install whatweb nikto dirb"
        echo -e "  # - subfinder : go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        echo -e "  # - httprobe : go install github.com/tomnomnom/httprobe@latest"
        echo -e "  # - waybackurls : go install github.com/tomnomnom/waybackurls@latest"
        echo -e "  # - dnsrecon : pip install dnsrecon"
        echo -e "\n${RED}[!] Certaines dépendances sont manquantes. Veuillez les installer avant de continuer.${NC}"
        exit 1
    else
        echo -e "${GREEN}[+] Toutes les dépendances sont installées.${NC}\n"
    fi
    
    # Vérifier la version de Bash
    if [ "${BASH_VERSINFO:-0}" -lt 4 ]; then
        echo -e "${YELLOW}[!] Attention : Bash version ${BASH_VERSION} détectée. Bash 4.0 ou supérieur est recommandé.${NC}"
        read -p "Voulez-vous continuer malgré tout ? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${YELLOW}[!] Warning: Some features may require root privileges${NC}"
        return 1
    fi
    return 0
}

init_directories() {
    mkdir -p "$LOG_DIR" "$REPORTS_DIR" "$TEMP_DIR"
    if [ $? -ne 0 ]; then
        echo -e "${RED}[!] Failed to create required directories${NC}"
        exit 1
    fi
}

load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        echo -e "${BLUE}[*]${NC} Loading configuration from $CONFIG_FILE"
        source "$CONFIG_FILE"
    fi
}

log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "$level" in
        "INFO") color="$BLUE" ;;
        "SUCCESS") color="$GREEN" ;;
        "WARNING") color="$YELLOW" ;;
        "ERROR") color="$RED" ;;
        "DEBUG") color="$MAGENTA" ;;
        *) color="$NC" ;;
    esac
    
    echo -e "${color}[${level}]${NC} $message"
    
    # Log to file
    if [ "$level" != "DEBUG" ] || [ "$DEBUG" -eq 1 ]; then
        echo "[$timestamp] [$level] $message" >> "$LOG_DIR/webpredator_$(date +%Y%m%d).log"
    fi
}

cleanup() {
    log "INFO" "Cleaning up temporary files..."
    rm -rf "$TEMP_DIR"
    log "SUCCESS" "Cleanup complete"
}

# ================================================
# Main Functions
# ================================================

reconnaissance() {
    log "INFO" "Starting reconnaissance on $TARGET"
    
    # Basic whois lookup
    log "INFO" "Running WHOIS lookup..."
    whois "$TARGET" > "$TEMP_DIR/whois.txt" 2>&1 || log "WARNING" "WHOIS lookup failed"
    
    # DNS enumeration
    log "INFO" "Enumerating DNS records..."
    dnsrecon -d "$TARGET" -t std,axfr,bing -j "$TEMP_DIR/dnsrecon.json" >/dev/null 2>&1 || \
        log "WARNING" "DNS enumeration failed"
    
    # Subdomain enumeration
    log "INFO" "Enumerating subdomains..."
    subfinder -d "$TARGET" -o "$TEMP_DIR/subdomains.txt" >/dev/null 2>&1 || \
        log "WARNING" "Subdomain enumeration failed"
    
    log "SUCCESS" "Reconnaissance completed"
}

scan_target() {
    log "INFO" "Starting scan on $TARGET"
    
    # Nmap scan
    log "INFO" "Running Nmap scan..."
    nmap -sV -sC -oA "$TEMP_DIR/nmap_scan" "$TARGET" >/dev/null 2>&1 || \
        log "WARNING" "Nmap scan failed"
    
    # Web server fingerprinting
    log "INFO" "Fingerprinting web server..."
    whatweb -v -a 3 "$TARGET" > "$TEMP_DIR/whatweb.txt" 2>&1 || \
        log "WARNING" "Web server fingerprinting failed"
    
    # Directory brute-forcing
    log "INFO" "Starting directory brute-forcing..."
    dirb "https://$TARGET" -o "$TEMP_DIR/dirb.txt" >/dev/null 2>&1 || \
        log "WARNING" "Directory brute-forcing failed"
    
    log "SUCCESS" "Scan completed"
}

exploit_checks() {
    log "INFO" "Starting vulnerability checks..."
    
    # Nikto scan
    log "INFO" "Running Nikto scan..."
    nikto -h "$TARGET" -output "$TEMP_DIR/nikto.html" -Format htm >/dev/null 2>&1 || \
        log "WARNING" "Nikto scan failed"
    
    # SQL injection check with sqlmap
    log "INFO" "Checking for SQL injection vulnerabilities..."
    sqlmap -u "https://$TARGET" --batch --crawl=2 --level=3 --risk=2 --output-dir="$TEMP_DIR/sqlmap" >/dev/null 2>&1 || \
        log "WARNING" "SQL injection check failed"
    
    log "SUCCESS" "Vulnerability checks completed"
}

generate_report() {
    log "INFO" "Generating $OUTPUT_FORMAT report..."
    
    # This is a simplified example - in a real scenario, you would process the collected data
    local report_file="$REPORTS_DIR/webpredator_${TARGET//\./_}_$(date +%Y%m%d_%H%M%S).$OUTPUT_FORMAT"
    
    case "$OUTPUT_FORMAT" in
        "html")
            echo "<html><body><h1>WebPredator Report for $TARGET</h1>" > "$report_file"
            echo "<h2>Scan Summary</h2>" >> "$report_file"
            echo "<p>Date: $(date)</p>" >> "$report_file"
            echo "<p>Target: $TARGET</p>" >> "$report_file"
            echo "<p>Scan Type: $SCAN_TYPE</p>" >> "$report_file"
            echo "</body></html>" >> "$report_file"
            ;;
        "json")
            echo "{\"target\":\"$TARGET\",\"date\":\"$(date -Iseconds)\",\"scan_type\":\"$SCAN_TYPE\"}" > "$report_file"
            ;;
        "csv")
            echo "target,date,scan_type" > "$report_file"
            echo "$TARGET,$(date -Iseconds),$SCAN_TYPE" >> "$report_file"
            ;;
        *)
            echo "WebPredator Report for $TARGET" > "$report_file"
            echo "Date: $(date)" >> "$report_file"
            echo "Target: $TARGET" >> "$report_file"
            echo "Scan Type: $SCAN_TYPE" >> "$report_file"
            ;;
    esac
    
    log "SUCCESS" "Report generated: $report_file"
}

# ================================================
# Main Execution
# ================================================

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--target)
            TARGET="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_FORMAT="$2"
            shift 2
            ;;
        -T|--threads)
            THREADS="$2"
            shift 2
            ;;
        -s|--scan)
            SCAN_TYPE="$2"
            shift 2
            ;;
        -d|--depth)
            DEPTH="$2"
            shift 2
            ;;
        -c|--config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        -u|--user-agent)
            USER_AGENT="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        -D|--debug)
            DEBUG=1
            set -x
            shift
            ;;
        -h|--help)
            show_help
            ;;
        *)
            echo -e "${RED}[!] Unknown parameter: $1${NC}"
            show_help
            ;;
    esac
done

# Main execution
main() {
    show_banner
    
    # Afficher le logo WebPredator
    show_webpredator_banner
    
    # Valider la cible
    if [ -z "$TARGET" ] && [ "$1" != "-h" ] && [ "$1" != "--help" ]; then
        log "ERROR" "Aucune cible spécifiée. Utilisez -t ou --target pour spécifier une cible."
        log "INFO" "Utilisez --help pour afficher l'aide complète.\n"
        exit 1
    fi
    
    # Vérifier les dépendances dès le début
    check_dependencies
    
    # Check dependencies
    check_dependencies
    
    # Check for root privileges
    check_root
    
    # Initialize directories
    init_directories
    
    # Load configuration
    load_config
    
    # Set up trap for cleanup on exit
    trap cleanup EXIT
    
    log "INFO" "Starting WebPredator v$VERSION"
    log "INFO" "Target: $TARGET"
    log "INFO" "Scan Type: $SCAN_TYPE"
    log "INFO" "Threads: $THREADS"
    
    # Main workflow
    reconnaissance
    scan_target
    
    if [ "$SCAN_TYPE" = "full" ]; then
        exploit_checks
    fi
    
    generate_report
    
    log "SUCCESS" "WebPredator scan completed successfully"
}

# Run main function
main "$@"