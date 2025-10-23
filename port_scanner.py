#!/usr/bin/env python3
"""
EasyPortScanner - Scanner di porte TCP semplice e veloce
Utilizzo per test di sicurezza e amministrazione di rete autorizzati
"""

import socket
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import threading

# Lock per thread-safe printing
print_lock = threading.Lock()

class PortScanner:
    def __init__(self, target, timeout=1, threads=100):
        """
        Inizializza lo scanner di porte

        Args:
            target (str): Hostname o IP da scansionare
            timeout (float): Timeout per connessione in secondi
            threads (int): Numero di thread da utilizzare
        """
        self.target = target
        self.timeout = timeout
        self.threads = threads
        self.open_ports = []

    def resolve_target(self):
        """Risolve l'hostname in indirizzo IP"""
        try:
            self.ip = socket.gethostbyname(self.target)
            return True
        except socket.gaierror:
            print(f"[-] Errore: Impossibile risolvere l'hostname '{self.target}'")
            return False

    def scan_port(self, port):
        """
        Scansiona una singola porta

        Args:
            port (int): Numero di porta da scansionare

        Returns:
            tuple: (port, is_open, service_name)
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.ip, port))
            sock.close()

            if result == 0:
                # Porta aperta, tenta di ottenere il nome del servizio
                try:
                    service = socket.getservbyport(port, 'tcp')
                except:
                    service = "unknown"

                return (port, True, service)
            else:
                return (port, False, None)

        except socket.timeout:
            return (port, False, None)
        except socket.error:
            return (port, False, None)
        except KeyboardInterrupt:
            sys.exit(0)

    def scan_ports(self, port_list):
        """
        Scansiona una lista di porte usando multi-threading

        Args:
            port_list (list): Lista di porte da scansionare
        """
        print(f"\n[*] Inizio scansione di {self.target} ({self.ip})")
        print(f"[*] Scansione di {len(port_list)} porte con {self.threads} thread")
        print(f"[*] Timeout: {self.timeout}s")
        print(f"[*] Ora inizio: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 60)

        try:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                # Sottometti tutti i job
                future_to_port = {executor.submit(self.scan_port, port): port
                                 for port in port_list}

                # Processa i risultati man mano che arrivano
                for future in as_completed(future_to_port):
                    port, is_open, service = future.result()

                    if is_open:
                        self.open_ports.append(port)
                        with print_lock:
                            print(f"[+] Porta {port:5d}/tcp  aperta  {service}")

        except KeyboardInterrupt:
            print("\n[-] Scansione interrotta dall'utente")
            executor.shutdown(wait=False)
            sys.exit(0)

    def print_summary(self):
        """Stampa il riepilogo della scansione"""
        print("-" * 60)
        print(f"[*] Scansione completata: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[*] Porte aperte trovate: {len(self.open_ports)}")

        if self.open_ports:
            print(f"[*] Lista porte aperte: {sorted(self.open_ports)}")

def parse_port_range(port_string):
    """
    Converte una stringa di porte in una lista di numeri di porta

    Args:
        port_string (str): Stringa tipo "80", "80,443", "1-100", "20-25,80,443"

    Returns:
        list: Lista di numeri di porta
    """
    ports = []

    try:
        # Gestisce range e porte singole separate da virgola
        parts = port_string.split(',')

        for part in parts:
            if '-' in part:
                # Range di porte
                start, end = part.split('-')
                start, end = int(start.strip()), int(end.strip())

                if start > end:
                    raise ValueError("Range invalido: inizio > fine")
                if start < 1 or end > 65535:
                    raise ValueError("Porte devono essere tra 1 e 65535")

                ports.extend(range(start, end + 1))
            else:
                # Porta singola
                port = int(part.strip())
                if port < 1 or port > 65535:
                    raise ValueError("Porta deve essere tra 1 e 65535")
                ports.append(port)

        return sorted(list(set(ports)))  # Rimuove duplicati e ordina

    except ValueError as e:
        raise argparse.ArgumentTypeError(f"Formato porte invalido: {e}")

def main():
    """Funzione principale"""
    parser = argparse.ArgumentParser(
        description='EasyPortScanner - Scanner di porte TCP',
        epilog='Esempi:\n'
               '  %(prog)s 192.168.1.1 -p 80\n'
               '  %(prog)s example.com -p 1-1000\n'
               '  %(prog)s 10.0.0.1 -p 22,80,443,8080\n'
               '  %(prog)s scanme.nmap.org -p 1-65535 -t 200',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('target', help='Hostname o indirizzo IP da scansionare')
    parser.add_argument('-p', '--ports',
                       type=parse_port_range,
                       default='1-1000',
                       help='Porte da scansionare (es: 80, 1-100, 20-25,80,443) [default: 1-1000]')
    parser.add_argument('-t', '--threads',
                       type=int,
                       default=100,
                       help='Numero di thread da utilizzare [default: 100]')
    parser.add_argument('--timeout',
                       type=float,
                       default=1.0,
                       help='Timeout connessione in secondi [default: 1.0]')

    args = parser.parse_args()

    # Validazione argomenti
    if args.threads < 1:
        parser.error("Il numero di thread deve essere >= 1")
    if args.timeout <= 0:
        parser.error("Il timeout deve essere > 0")

    # Crea e avvia scanner
    scanner = PortScanner(args.target, timeout=args.timeout, threads=args.threads)

    # Risolve target
    if not scanner.resolve_target():
        sys.exit(1)

    # Scansiona porte
    try:
        scanner.scan_ports(args.ports)
        scanner.print_summary()
    except KeyboardInterrupt:
        print("\n[-] Programma terminato")
        sys.exit(0)

if __name__ == "__main__":
    main()
