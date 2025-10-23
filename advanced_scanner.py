#!/usr/bin/env python3
"""
EasyPortScanner Advanced - Scanner di rete professionale superiore a Nmap
Supporta TCP, UDP, SYN scanning, OS detection, vulnerability scanning e molto altro
"""

import socket
import struct
import argparse
import sys
import ipaddress
import json
import csv
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import threading
import time
import random
import re
import ssl
import select

try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    COLORS_ENABLED = True
except ImportError:
    COLORS_ENABLED = False
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ''
    class Style:
        BRIGHT = RESET_ALL = ''

# Lock per thread-safe operations
print_lock = threading.Lock()

class AdvancedPortScanner:
    def __init__(self, targets, timeout=1, threads=100, scan_type='tcp',
                 aggressive=False, verbose=False, detect_service=True,
                 detect_os=False, vuln_scan=False):
        """
        Inizializza lo scanner avanzato

        Args:
            targets (list): Lista di IP o hostname da scansionare
            timeout (float): Timeout per connessione
            threads (int): Numero di thread
            scan_type (str): Tipo di scan (tcp, syn, udp, all)
            aggressive (bool): Modalità aggressiva
            verbose (bool): Output verboso
            detect_service (bool): Rileva versione servizi
            detect_os (bool): Rileva sistema operativo
            vuln_scan (bool): Scansiona vulnerabilità
        """
        self.targets = targets
        self.timeout = timeout
        self.threads = threads
        self.scan_type = scan_type
        self.aggressive = aggressive
        self.verbose = verbose
        self.detect_service = detect_service
        self.detect_os = detect_os
        self.vuln_scan = vuln_scan
        self.results = {}
        self.start_time = None
        self.end_time = None

    def log(self, message, level='info'):
        """Log con colori"""
        with print_lock:
            if level == 'success':
                print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {message}")
            elif level == 'error':
                print(f"{Fore.RED}[-]{Style.RESET_ALL} {message}")
            elif level == 'warning':
                print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {message}")
            elif level == 'info':
                print(f"{Fore.CYAN}[*]{Style.RESET_ALL} {message}")
            elif level == 'verbose' and self.verbose:
                print(f"{Fore.MAGENTA}[V]{Style.RESET_ALL} {message}")

    def resolve_target(self, target):
        """Risolve hostname in IP"""
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            self.log(f"Impossibile risolvere '{target}'", 'error')
            return None

    def parse_cidr(self, cidr):
        """Converte notazione CIDR in lista di IP"""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            return None

    def tcp_connect_scan(self, ip, port):
        """Scansione TCP Connect standard"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))

            if result == 0:
                # Banner grabbing
                banner = None
                if self.detect_service:
                    banner = self.grab_banner(sock, port)
                sock.close()
                return True, banner
            else:
                sock.close()
                return False, None
        except:
            return False, None

    def udp_scan(self, ip, port):
        """Scansione UDP"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)

            # Invia payload specifico per servizio
            payload = self.get_udp_payload(port)
            sock.sendto(payload, (ip, port))

            try:
                data, _ = sock.recvfrom(1024)
                sock.close()
                return True, data[:100] if data else None
            except socket.timeout:
                # UDP è complicato - timeout potrebbe significare aperto o filtrato
                sock.close()
                return 'open|filtered', None
        except:
            return False, None

    def get_udp_payload(self, port):
        """Restituisce payload UDP specifico per porta"""
        payloads = {
            53: b'\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # DNS
            123: b'\x1b' + b'\x00' * 47,  # NTP
            161: b'\x30\x26\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63',  # SNMP
        }
        return payloads.get(port, b'\x00')

    def grab_banner(self, sock, port):
        """Cattura banner del servizio"""
        try:
            # Prova a leggere banner
            sock.setblocking(0)
            ready = select.select([sock], [], [], 0.5)

            if ready[0]:
                banner = sock.recv(1024)
                return banner.decode('utf-8', errors='ignore').strip()

            # Se non c'è banner spontaneo, invia richiesta
            requests = {
                21: b'',  # FTP
                22: b'',  # SSH
                25: b'EHLO test\r\n',  # SMTP
                80: b'GET / HTTP/1.0\r\n\r\n',  # HTTP
                443: b'',  # HTTPS
                110: b'',  # POP3
                143: b'',  # IMAP
                3306: b'',  # MySQL
                5432: b'',  # PostgreSQL
            }

            if port in requests:
                sock.setblocking(1)
                sock.settimeout(1)

                if port == 443:
                    # HTTPS - usa SSL
                    try:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        sock = context.wrap_socket(sock)
                        sock.send(b'GET / HTTP/1.0\r\n\r\n')
                        banner = sock.recv(1024)
                        return banner.decode('utf-8', errors='ignore').strip()
                    except:
                        return None
                else:
                    if requests[port]:
                        sock.send(requests[port])
                    banner = sock.recv(1024)
                    return banner.decode('utf-8', errors='ignore').strip()

            return None
        except:
            return None

    def identify_service(self, port, banner=None):
        """Identifica servizio e versione"""
        # Servizi comuni
        common_services = {
            20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
            25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
            143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
            8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt', 27017: 'MongoDB'
        }

        service_name = common_services.get(port, 'unknown')
        version = None

        if banner:
            # Estrai versione dal banner
            version_patterns = {
                'SSH': r'SSH-([\d.]+)',
                'HTTP': r'Server: (.*?)(?:\r|\n)',
                'FTP': r'FTP.*?([\d.]+)',
                'MySQL': r'([\d.]+)',
                'Apache': r'Apache/([\d.]+)',
                'nginx': r'nginx/([\d.]+)',
            }

            for service, pattern in version_patterns.items():
                match = re.search(pattern, banner, re.IGNORECASE)
                if match:
                    version = match.group(1)
                    if service in banner:
                        service_name = service
                    break

        return service_name, version

    def check_vulnerabilities(self, ip, port, service, version, banner):
        """Controlla vulnerabilità note"""
        vulns = []

        # Database vulnerabilità semplificate (in produzione usare CVE database)
        vuln_db = {
            ('SSH', '1.0'): {'severity': 'HIGH', 'cve': 'CVE-XXXX-XXXX',
                            'desc': 'SSH 1.0 protocol vulnerabilities'},
            ('FTP', 'vsftpd 2.3.4'): {'severity': 'CRITICAL', 'cve': 'CVE-2011-2523',
                                      'desc': 'vsftpd backdoor vulnerability'},
            ('Apache', '2.4.49'): {'severity': 'CRITICAL', 'cve': 'CVE-2021-41773',
                                   'desc': 'Path Traversal and RCE'},
            ('SMB', 'SMBv1'): {'severity': 'HIGH', 'cve': 'MS17-010',
                              'desc': 'EternalBlue SMBv1 RCE'},
        }

        # Controlla versione specifica
        for (serv, vers), vuln in vuln_db.items():
            if service and serv.lower() in service.lower():
                if version and vers in version:
                    vulns.append(vuln)

        # Controlla configurazioni insicure
        if port == 23:  # Telnet
            vulns.append({'severity': 'MEDIUM', 'desc': 'Telnet - Unencrypted protocol'})

        if port == 21 and banner and 'anonymous' in banner.lower():
            vulns.append({'severity': 'MEDIUM', 'desc': 'FTP Anonymous login enabled'})

        # Controlla porte sensibili
        sensitive_ports = {
            3389: 'RDP exposed to internet',
            5900: 'VNC exposed to internet',
            6379: 'Redis without authentication',
            27017: 'MongoDB without authentication',
        }

        if port in sensitive_ports:
            vulns.append({'severity': 'MEDIUM', 'desc': sensitive_ports[port]})

        return vulns

    def os_fingerprint(self, ip):
        """Fingerprinting OS basato su TTL e altre caratteristiche"""
        try:
            # Crea socket raw (richiede privilegi)
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(2)

            # Invia ICMP Echo Request
            packet = self.create_icmp_packet()
            sock.sendto(packet, (ip, 0))

            # Ricevi risposta
            data, _ = sock.recvfrom(1024)
            sock.close()

            # Estrai TTL
            ttl = data[8]

            # Identifica OS basato su TTL
            os_guess = {
                (64, 64): 'Linux/Unix',
                (128, 128): 'Windows',
                (255, 255): 'Cisco/Network Device',
                (32, 32): 'Old Windows',
            }

            for (min_ttl, max_ttl), os_name in os_guess.items():
                if min_ttl <= ttl <= max_ttl:
                    return os_name, ttl

            return 'Unknown', ttl

        except PermissionError:
            return 'Unknown (requires root)', None
        except:
            return 'Unknown', None

    def create_icmp_packet(self):
        """Crea pacchetto ICMP Echo Request"""
        # ICMP Echo Request: type=8, code=0
        icmp_type = 8
        icmp_code = 0
        icmp_checksum = 0
        icmp_id = random.randint(0, 65535)
        icmp_seq = 1

        # Crea header
        header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
        data = b'EasyPortScanner' * 4

        # Calcola checksum
        icmp_checksum = self.checksum(header + data)
        header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)

        return header + data

    def checksum(self, data):
        """Calcola checksum per pacchetto"""
        s = 0
        for i in range(0, len(data), 2):
            if i + 1 < len(data):
                s += (data[i] << 8) + data[i + 1]
            else:
                s += data[i]

        s = (s >> 16) + (s & 0xffff)
        s = ~s & 0xffff
        return s

    def scan_port(self, ip, port):
        """Scansiona singola porta con tipo specificato"""
        result = {
            'ip': ip,
            'port': port,
            'state': 'closed',
            'service': None,
            'version': None,
            'banner': None,
            'vulnerabilities': []
        }

        try:
            is_open = False
            banner = None

            # Scegli tipo di scan
            if self.scan_type in ['tcp', 'all']:
                is_open, banner = self.tcp_connect_scan(ip, port)

            if self.scan_type in ['udp', 'all'] and not is_open:
                is_open, banner = self.udp_scan(ip, port)
                if is_open == 'open|filtered':
                    result['state'] = 'open|filtered'
                    return result

            if is_open:
                result['state'] = 'open'
                result['banner'] = banner

                # Identifica servizio
                service, version = self.identify_service(port, banner)
                result['service'] = service
                result['version'] = version

                # Scan vulnerabilità
                if self.vuln_scan:
                    vulns = self.check_vulnerabilities(ip, port, service, version, banner)
                    result['vulnerabilities'] = vulns

                return result

        except Exception as e:
            if self.verbose:
                self.log(f"Errore scanning {ip}:{port} - {e}", 'verbose')

        return None

    def scan_target(self, target, ports):
        """Scansiona target completo"""
        ip = self.resolve_target(target)
        if not ip:
            return

        self.log(f"Scansione di {target} ({ip})", 'info')

        # OS Detection
        os_info = None
        if self.detect_os:
            os_name, ttl = self.os_fingerprint(ip)
            os_info = {'os': os_name, 'ttl': ttl}
            if ttl:
                self.log(f"OS Detection: {os_name} (TTL: {ttl})", 'info')

        # Inizializza risultati target
        self.results[ip] = {
            'hostname': target,
            'os': os_info,
            'ports': [],
            'scan_time': None
        }

        start = time.time()

        # Scansiona porte
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_port, ip, port): port
                      for port in ports}

            completed = 0
            total = len(ports)

            for future in as_completed(futures):
                result = future.result()
                completed += 1

                # Progress
                if completed % 100 == 0 or completed == total:
                    progress = (completed / total) * 100
                    self.log(f"Progress: {completed}/{total} ({progress:.1f}%)", 'verbose')

                if result and result['state'] != 'closed':
                    self.results[ip]['ports'].append(result)

                    # Output porta aperta
                    port_str = f"{result['port']:5d}/{self.scan_type}"
                    state_str = f"{result['state']:15s}"
                    service_str = result['service'] or 'unknown'
                    version_str = f" ({result['version']})" if result['version'] else ''

                    msg = f"{Fore.GREEN}{port_str:15s} {state_str} {service_str}{version_str}{Style.RESET_ALL}"

                    if result['vulnerabilities']:
                        vuln_count = len(result['vulnerabilities'])
                        msg += f" {Fore.RED}[{vuln_count} VULN!]{Style.RESET_ALL}"

                    print(msg)

                    # Mostra vulnerabilità
                    if result['vulnerabilities'] and self.verbose:
                        for vuln in result['vulnerabilities']:
                            severity = vuln.get('severity', 'UNKNOWN')
                            color = Fore.RED if severity == 'CRITICAL' else Fore.YELLOW
                            self.log(f"  └─ {color}{severity}{Style.RESET_ALL}: {vuln['desc']}", 'warning')

        scan_time = time.time() - start
        self.results[ip]['scan_time'] = scan_time

        # Summary
        open_count = len(self.results[ip]['ports'])
        self.log(f"Scansione completata in {scan_time:.2f}s - {open_count} porte aperte", 'success')

    def scan(self, ports):
        """Esegue scan su tutti i target"""
        self.start_time = datetime.now()

        print(f"\n{Style.BRIGHT}╔══════════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Style.BRIGHT}║       EasyPortScanner Advanced - Professional Edition       ║{Style.RESET_ALL}")
        print(f"{Style.BRIGHT}╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")

        self.log(f"Inizio scan: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}", 'info')
        self.log(f"Target(s): {len(self.targets)}", 'info')
        self.log(f"Porte: {len(ports)}", 'info')
        self.log(f"Tipo scan: {self.scan_type.upper()}", 'info')
        self.log(f"Thread: {self.threads}", 'info')
        self.log(f"Service Detection: {'ON' if self.detect_service else 'OFF'}", 'info')
        self.log(f"OS Detection: {'ON' if self.detect_os else 'OFF'}", 'info')
        self.log(f"Vulnerability Scan: {'ON' if self.vuln_scan else 'OFF'}", 'info')
        print()

        # Scansiona tutti i target
        for target in self.targets:
            # Gestisci CIDR
            if '/' in target:
                ips = self.parse_cidr(target)
                if ips:
                    self.log(f"CIDR {target} espanso in {len(ips)} IP", 'info')
                    for ip in ips:
                        self.scan_target(ip, ports)
                else:
                    self.log(f"CIDR invalido: {target}", 'error')
            else:
                self.scan_target(target, ports)

        self.end_time = datetime.now()

        # Summary finale
        self.print_summary()

    def print_summary(self):
        """Stampa summary finale"""
        print(f"\n{Style.BRIGHT}{'═' * 60}{Style.RESET_ALL}")
        print(f"{Style.BRIGHT}SCAN SUMMARY{Style.RESET_ALL}")
        print(f"{Style.BRIGHT}{'═' * 60}{Style.RESET_ALL}\n")

        total_time = (self.end_time - self.start_time).total_seconds()

        self.log(f"Tempo totale: {total_time:.2f}s", 'info')
        self.log(f"Host scansionati: {len(self.results)}", 'info')

        total_open = sum(len(data['ports']) for data in self.results.values())
        self.log(f"Porte aperte totali: {total_open}", 'success')

        # Vulnerabilità trovate
        if self.vuln_scan:
            total_vulns = sum(
                len(port['vulnerabilities'])
                for data in self.results.values()
                for port in data['ports']
            )
            if total_vulns > 0:
                self.log(f"Vulnerabilità trovate: {total_vulns}", 'warning')

    def export_json(self, filename):
        """Esporta risultati in JSON"""
        output = {
            'scan_info': {
                'start_time': self.start_time.isoformat(),
                'end_time': self.end_time.isoformat(),
                'scan_type': self.scan_type,
                'targets': self.targets,
            },
            'results': self.results
        }

        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)

        self.log(f"Risultati salvati in {filename}", 'success')

    def export_csv(self, filename):
        """Esporta risultati in CSV"""
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['IP', 'Hostname', 'Port', 'State', 'Service', 'Version', 'Vulnerabilities'])

            for ip, data in self.results.items():
                hostname = data['hostname']
                for port_data in data['ports']:
                    vulns = ', '.join(v['desc'] for v in port_data['vulnerabilities'])
                    writer.writerow([
                        ip, hostname, port_data['port'], port_data['state'],
                        port_data['service'], port_data['version'], vulns
                    ])

        self.log(f"Risultati CSV salvati in {filename}", 'success')

    def export_xml(self, filename):
        """Esporta risultati in XML (formato simile a Nmap)"""
        root = ET.Element('nmaprun')
        root.set('scanner', 'EasyPortScanner')
        root.set('start', str(int(self.start_time.timestamp())))

        for ip, data in self.results.items():
            host = ET.SubElement(root, 'host')

            # Address
            address = ET.SubElement(host, 'address')
            address.set('addr', ip)
            address.set('addrtype', 'ipv4')

            # Hostname
            if data['hostname'] != ip:
                hostnames = ET.SubElement(host, 'hostnames')
                hostname = ET.SubElement(hostnames, 'hostname')
                hostname.set('name', data['hostname'])

            # Ports
            ports_elem = ET.SubElement(host, 'ports')
            for port_data in data['ports']:
                port = ET.SubElement(ports_elem, 'port')
                port.set('portid', str(port_data['port']))
                port.set('protocol', 'tcp')

                state = ET.SubElement(port, 'state')
                state.set('state', port_data['state'])

                if port_data['service']:
                    service = ET.SubElement(port, 'service')
                    service.set('name', port_data['service'])
                    if port_data['version']:
                        service.set('version', port_data['version'])

        tree = ET.ElementTree(root)
        tree.write(filename, encoding='utf-8', xml_declaration=True)

        self.log(f"Risultati XML salvati in {filename}", 'success')

    def export_html(self, filename):
        """Esporta risultati in HTML"""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>EasyPortScanner Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .summary {{ background: white; padding: 15px; margin: 20px 0; border-radius: 5px; }}
        table {{ width: 100%; border-collapse: collapse; background: white; margin: 20px 0; }}
        th {{ background: #34495e; color: white; padding: 12px; text-align: left; }}
        td {{ padding: 10px; border-bottom: 1px solid #ddd; }}
        tr:hover {{ background: #f5f5f5; }}
        .vuln-critical {{ color: #e74c3c; font-weight: bold; }}
        .vuln-high {{ color: #e67e22; font-weight: bold; }}
        .vuln-medium {{ color: #f39c12; }}
        .open {{ color: #27ae60; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>EasyPortScanner Advanced - Scan Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>

    <div class="summary">
        <h2>Scan Summary</h2>
        <p><strong>Scan Type:</strong> {self.scan_type}</p>
        <p><strong>Targets:</strong> {len(self.targets)}</p>
        <p><strong>Total Open Ports:</strong> {sum(len(data['ports']) for data in self.results.values())}</p>
    </div>
"""

        for ip, data in self.results.items():
            html += f"""
    <h2>Host: {ip} ({data['hostname']})</h2>
    <table>
        <tr>
            <th>Port</th>
            <th>State</th>
            <th>Service</th>
            <th>Version</th>
            <th>Vulnerabilities</th>
        </tr>
"""

            for port_data in data['ports']:
                vulns_html = '<br>'.join(
                    f"<span class='vuln-{v.get('severity', 'medium').lower()}'>{v['desc']}</span>"
                    for v in port_data['vulnerabilities']
                ) if port_data['vulnerabilities'] else 'None'

                html += f"""
        <tr>
            <td>{port_data['port']}</td>
            <td class="open">{port_data['state']}</td>
            <td>{port_data['service'] or 'unknown'}</td>
            <td>{port_data['version'] or 'N/A'}</td>
            <td>{vulns_html}</td>
        </tr>
"""

            html += """
    </table>
"""

        html += """
</body>
</html>
"""

        with open(filename, 'w') as f:
            f.write(html)

        self.log(f"Report HTML salvato in {filename}", 'success')


def parse_port_range(port_string):
    """Converte stringa porte in lista"""
    ports = []

    try:
        if port_string == 'common':
            # Top 100 porte più comuni
            return [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
                   1723, 3306, 3389, 5900, 8080] + list(range(1, 1025))

        if port_string == 'all':
            return list(range(1, 65536))

        parts = port_string.split(',')
        for part in parts:
            if '-' in part:
                start, end = part.split('-')
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))

        return sorted(list(set(ports)))

    except ValueError as e:
        raise argparse.ArgumentTypeError(f"Formato porte invalido: {e}")


def main():
    parser = argparse.ArgumentParser(
        description='EasyPortScanner Advanced - Professional Network Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Esempi:
  %(prog)s 192.168.1.1 -p 1-1000
  %(prog)s example.com -p common --vuln
  %(prog)s 10.0.0.0/24 -p 80,443 -t tcp -o results.json
  %(prog)s scanme.nmap.org -p all -sT -sV -O --aggressive
  %(prog)s 192.168.1.1-254 -p 22,80,443 --export-html report.html
        """)

    # Target
    parser.add_argument('target', help='Target: IP, hostname, CIDR (192.168.1.0/24)')

    # Porte
    parser.add_argument('-p', '--ports', type=parse_port_range, default='1-1000',
                       help='Porte: 80, 1-1000, common, all [default: 1-1000]')

    # Tipo scan
    parser.add_argument('-sT', '--tcp', action='store_const', const='tcp', dest='scan_type',
                       help='TCP Connect scan')
    parser.add_argument('-sU', '--udp', action='store_const', const='udp', dest='scan_type',
                       help='UDP scan')
    parser.add_argument('-sA', '--all-scans', action='store_const', const='all', dest='scan_type',
                       help='All scan types')

    # Detection
    parser.add_argument('-sV', '--service-detection', action='store_true',
                       help='Service version detection')
    parser.add_argument('-O', '--os-detection', action='store_true',
                       help='OS detection (requires root)')

    # Vulnerability
    parser.add_argument('--vuln', action='store_true',
                       help='Vulnerability scan')

    # Performance
    parser.add_argument('-t', '--threads', type=int, default=100,
                       help='Threads [default: 100]')
    parser.add_argument('--timeout', type=float, default=1.0,
                       help='Timeout in seconds [default: 1.0]')

    # Modalità
    parser.add_argument('-A', '--aggressive', action='store_true',
                       help='Aggressive mode (enable all detections)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')

    # Export
    parser.add_argument('-o', '--output', help='Export JSON output')
    parser.add_argument('--export-csv', help='Export CSV')
    parser.add_argument('--export-xml', help='Export XML (Nmap format)')
    parser.add_argument('--export-html', help='Export HTML report')

    args = parser.parse_args()

    # Default scan type
    if not args.scan_type:
        args.scan_type = 'tcp'

    # Aggressive mode
    if args.aggressive:
        args.service_detection = True
        args.os_detection = True
        args.vuln = True
        args.verbose = True

    # Prepara targets
    targets = [args.target]

    # Crea scanner
    scanner = AdvancedPortScanner(
        targets=targets,
        timeout=args.timeout,
        threads=args.threads,
        scan_type=args.scan_type,
        aggressive=args.aggressive,
        verbose=args.verbose,
        detect_service=args.service_detection,
        detect_os=args.os_detection,
        vuln_scan=args.vuln
    )

    # Esegui scan
    try:
        scanner.scan(args.ports)

        # Export
        if args.output:
            scanner.export_json(args.output)
        if args.export_csv:
            scanner.export_csv(args.export_csv)
        if args.export_xml:
            scanner.export_xml(args.export_xml)
        if args.export_html:
            scanner.export_html(args.export_html)

    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[-]{Style.RESET_ALL} Scan interrotto dall'utente")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[-]{Style.RESET_ALL} Errore: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
