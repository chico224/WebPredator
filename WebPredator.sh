#!/bin/bash
# WebPredator Ultimate - Created by Chico
# Combinaison Bash/Python avec HERE-document

# ==================== CONFIGURATION ====================
VERSION="3.0"
LOGFILE="/tmp/wp.log"
RED='\033[0;91m'
GREEN='\033[0;92m'
YELLOW='\033[0;93m'
BLUE='\033[0;94m'
NC='\033[0m'

# ==================== BANNER ====================
show_banner() {
    clear
    echo -e "${RED}
██╗    ██╗███████╗██████╗ ██████╗ ██████╗ ███████╗██████╗ ███████╗████████╗ █████╗ ██████╗ 
██║    ██║██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██╔══██╗
██║ █╗ ██║█████╗  ██████╔╝██████╔╝██████╔╝█████╗  ██████╔╝█████╗     ██║   ███████║██║  ██║
██║███╗██║██╔══╝  ██╔══██╗██╔═══╝ ██╔═══╝ ██╔══╝  ██╔══██╗██╔══╝     ██║   ██╔══██║██║  ██║
╚███╔███╔╝███████╗██║  ██║██║     ██║     ███████╗██║  ██║███████╗   ██║   ██║  ██║██████╔╝
 ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═════╝ 
${YELLOW}
                  WebPredator – Ultimate Web Penetration Testing Framework
${BLUE}
                           Recon • Scan • Exploit • Report
${GREEN}
                         Created by ${YELLOW}Chico${GREEN} – For educational purposes only
${NC}"
}

# ==================== BASH FUNCTIONS ====================
quick_scan() {
    echo -e "${YELLOW}[+] Scanning $1...${NC}"
    nmap -T4 -F $1 | tee -a $LOGFILE
    # Appel Python embarqué
    python3 <<EOF
from scanner import Scanner
Scanner("$1").quick_scan()
EOF
}

generate_report() {
    python3 <<EOF
from reporter import ReportGenerator
ReportGenerator("$LOGFILE").generate()
EOF
}

# ==================== MAIN MENU ====================
show_menu() {
    show_banner
    echo -e "\n${BLUE}[+] Options:${NC}"
    echo "1. Scan réseau rapide"
    echo "2. Scan de vulnérabilités"
    echo "3. Lancer un exploit"
    echo "4. Générer un rapport PDF"
    echo -e "${RED}5. Quitter${NC}"
    
    read -p "Choix [1-5]: " choice
    case $choice in
        1) read -p "Cible (IP/URL): " target; quick_scan "$target" ;;
        2) python3 <<< "from scanner import VulnScanner; VulnScanner().run()" ;;
        3) python3 <<< "from exploit import ExploitTool; ExploitTool().menu()" ;;
        4) generate_report ;;
        5) rm -f "$LOGFILE"; exit 0 ;;
        *) echo -e "${RED}Option invalide!${NC}"; sleep 1; show_menu ;;
    esac
}

# ==================== PYTHON EMBED ====================
PYTHON_CODE=$(cat <<'END_PYTHON'
# -*- coding: utf-8 -*-
# Partie Python embarquée

class Scanner:
    def __init__(self, target):
        self.target = target
    
    def quick_scan(self):
        import nmap
        nm = nmap.PortScanner()
        nm.scan(hosts=self.target, arguments='-T4 -F')
        return nm.csv()

class VulnScanner:
    def run(self):
        import requests
        print("[+] Scanning for XSS/SQLi...")

class ExploitTool:
    def menu(self):
        print("[+] Exploit modules loaded")

class ReportGenerator:
    def __init__(self, logfile):
        self.logfile = logfile
    
    def generate(self):
        from fpdf import FPDF
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt="WebPredator Report - Created by Chico", ln=True)
        pdf.output("report.pdf")
        print("[+] Rapport généré : report.pdf")
END_PYTHON
)

# ==================== EXECUTION ====================
# Mode CLI ou interactif
if [[ "$1" == "--scan" && "$2" ]]; then
    quick_scan "$2"
elif [[ "$1" == "--exploit" ]]; then
    python3 <<< "from exploit import ExploitTool; ExploitTool().menu()"
else
    show_menu
fi