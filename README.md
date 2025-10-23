# EasyPortScanner

Scanner di porte TCP semplice, veloce e facile da usare scritto in Python.

## Caratteristiche

- 🚀 **Veloce**: Utilizza multi-threading per scansioni rapide
- 🎯 **Flessibile**: Supporta porte singole, range e combinazioni
- 🔍 **Informativo**: Identifica i servizi sulle porte aperte
- ⚙️ **Configurabile**: Timeout e numero di thread personalizzabili
- 💻 **Facile da usare**: Interfaccia a riga di comando intuitiva

## Requisiti

- Python 3.6 o superiore
- Nessuna dipendenza esterna (usa solo librerie standard Python)

## Installazione

```bash
git clone https://github.com/tuousername/EasyPortScanner.git
cd EasyPortScanner
chmod +x port_scanner.py
```

## Utilizzo

### Sintassi base

```bash
python3 port_scanner.py <target> [opzioni]
```

### Opzioni

- `target`: Hostname o indirizzo IP da scansionare (obbligatorio)
- `-p, --ports`: Porte da scansionare (default: 1-1000)
  - Porta singola: `80`
  - Range: `1-1000`
  - Multipli: `22,80,443`
  - Combinazione: `20-25,80,443,8080`
- `-t, --threads`: Numero di thread (default: 100)
- `--timeout`: Timeout connessione in secondi (default: 1.0)

### Esempi

**Scansione base (porte 1-1000):**
```bash
python3 port_scanner.py 192.168.1.1
```

**Scansionare una porta specifica:**
```bash
python3 port_scanner.py example.com -p 80
```

**Scansionare porte comuni:**
```bash
python3 port_scanner.py 192.168.1.1 -p 21,22,23,25,80,443,3306,8080
```

**Scansionare un range di porte:**
```bash
python3 port_scanner.py scanme.nmap.org -p 1-1000
```

**Scansione completa con più thread:**
```bash
python3 port_scanner.py 192.168.1.1 -p 1-65535 -t 200
```

**Scansione con timeout personalizzato:**
```bash
python3 port_scanner.py example.com -p 1-1000 --timeout 0.5
```

**Combinazione di porte e range:**
```bash
python3 port_scanner.py 10.0.0.1 -p 20-25,80,443,3000-3010,8080
```

## Output di esempio

```
[*] Inizio scansione di scanme.nmap.org (45.33.32.156)
[*] Scansione di 1000 porte con 100 thread
[*] Timeout: 1.0s
[*] Ora inizio: 2025-10-23 12:00:00
------------------------------------------------------------
[+] Porta    22/tcp  aperta  ssh
[+] Porta    80/tcp  aperta  http
[+] Porta   443/tcp  aperta  https
------------------------------------------------------------
[*] Scansione completata: 2025-10-23 12:00:15
[*] Porte aperte trovate: 3
[*] Lista porte aperte: [22, 80, 443]
```

## Note importanti

⚠️ **Uso legale**: Questo strumento deve essere utilizzato SOLO su sistemi di tua proprietà o per cui hai esplicita autorizzazione. La scansione non autorizzata di porte è illegale in molte giurisdizioni.

⚠️ **Scopi legittimi**: Questo strumento è destinato a:
- Test di sicurezza autorizzati
- Amministrazione di rete
- Audit di sicurezza
- Scopi educativi

## Performance

- **Thread**: Più thread = scansione più veloce, ma usa più risorse
  - Range consigliato: 50-200 thread
  - Default: 100 thread
- **Timeout**: Timeout più basso = scansione più veloce, ma potrebbe perdere porte aperte
  - Range consigliato: 0.5-2.0 secondi
  - Default: 1.0 secondo

## Risoluzione problemi

**"Troppi file aperti" error:**
```bash
# Aumenta il limite di file aperti (Linux/macOS)
ulimit -n 4096
```

**Scansione lenta:**
- Aumenta il numero di thread: `-t 200`
- Riduci il timeout: `--timeout 0.5`
- Scansiona un range di porte più piccolo

**Porte non rilevate:**
- Aumenta il timeout: `--timeout 2.0`
- Verifica che non ci siano firewall che bloccano

## Licenza

MIT License - Vedi file LICENSE per dettagli

## Contributi

I contributi sono benvenuti! Sentiti libero di aprire issue o pull request.

## Disclaimer

Questo strumento è fornito "così com'è" senza garanzie di alcun tipo. Gli autori non sono responsabili per eventuali danni o uso improprio. Utilizzare responsabilmente e solo su sistemi per cui hai l'autorizzazione.
