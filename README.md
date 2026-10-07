# Cyber Security Toolkit (v2.0)

A comprehensive, desktop-based cybersecurity utility suite built in Python with a modern GUI (`ttkbootstrap`), SQLite activity tracking, and diagnostic modules for defensive security auditing, network reconnaissance, and cryptographic analysis.

---

## Overview

The **Cyber Security Toolkit** brings essential day-to-day security utilities into a unified, dark-themed desktop console. It is designed for students, security enthusiasts, system administrators, and developers to analyze password strength, audit web servers, inspect network endpoints, examine SSL/TLS certificates, decode payload formats, and generate cryptographic digests without relying on disparate online tools.

---

## Features

### 1. Defensive Auditing & Web Inspection
* **HTTP Security Headers Analyzer**: Queries target websites and evaluates essential hardening headers (`Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`) with grading and server signature leakage detection.
* **SSL/TLS Certificate Checker**: Performs a TLS handshake to extract certificate subject, issuing authority, validity periods, expiration countdown, and negotiated cipher suites.
* **URL Inspector**: Heuristic URL validation evaluating HTTPS scheme usage, length thresholds, syntax anomalies, and hostname integrity.

### 2. Network Reconnaissance & Diagnostics
* **Port Scanner**: Multi-threaded socket scanner checking common service ports (21/FTP, 22/SSH, 25/SMTP, 53/DNS, 80/HTTP, 110/POP3, 143/IMAP, 443/HTTPS) with configurable timeout handling.
* **DNS Record Lookup**: Queries DNS records (`A`, `MX`, `NS`, `TXT`, `CNAME`, `PTR`) for any domain or hostname.
* **Ping & Latency Probe**: Measures round-trip latency (RTT) and packet loss to remote hosts using system ping utilities.
* **Subnet & CIDR Calculator**: Uses Python's native `ipaddress` library to calculate network address, broadcast address, netmask, wildcard mask, host address ranges, and total usable hosts.
* **IP Geolocation**: Resolves IP addresses to locate geographic region, city, ISP, and autonomous system numbers.

### 3. Cryptography, Ciphers & Encodings
* **Hash Generator**: Calculates cryptographic checksums (`MD5`, `SHA-256`) for local files via buffered chunk processing.
* **Universal Decoder & JWT Inspector**: Decodes multi-layer payloads across Base64, Hex, URL-encoding, HTML entities, and inspects JSON Web Token (JWT) header and payload claims.
* **Cipher & Encoding Suite**: Encodes and decodes classical algorithms including Caesar cipher, ROT13, Vigenère cipher, Hex, and Binary representations.
* **Password Strength Analyzer**: Evaluates entropy criteria including length, uppercase, lowercase, numeric digits, and special symbol presence.
* **Cryptographic Password Generator**: Generates high-entropy passwords with custom length and character set configurations.

### 4. Operations & Reporting
* **Local SQLite Audit Trail**: Automatically logs tool executions, inputs, and results in an on-device `security_toolkit.db` database.
* **Activity History & CSV Export**: Allows searching, reviewing, and exporting logged audit history.
* **Analytics Dashboard**: Visual usage statistics powered by embedded Matplotlib charts.

---

## Project Structure

```text
Cyber-Security-Toolkit/
├── assets/
│   └── logo2.ico                # Application window icon
├── checker.py                   # URL safety scoring logic
├── database.py                  # SQLite database persistence layer
├── hash_generator.py            # MD5 and SHA-256 file hashing
├── main_v2.py                   # Main GUI application (ttkbootstrap & Tkinter)
├── password_checker.py          # Password complexity validation logic
├── scanner.py                   # Socket-based TCP port scanning logic
├── .gitignore                   # Ignored build and runtime artifacts
├── requirements.txt             # Project dependencies
└── README.md                    # Project documentation
```

---

## Dependencies

* **Python 3.10+**
* `ttkbootstrap` – Modern Bootstrap-styled Tkinter UI framework
* `matplotlib` – Embedded chart generation in the Analytics module

All other libraries (`tkinter`, `sqlite3`, `socket`, `ssl`, `urllib`, `ipaddress`, `hashlib`, `json`, `subprocess`) are part of the Python Standard Library.

---

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/deswanth12/Cyber-Security-Toolkit.git
   cd Cyber-Security-Toolkit
   ```

2. **Create and activate a virtual environment (recommended):**
   ```bash
   # Linux / macOS
   python3 -m venv venv
   source venv/bin/activate

   # Windows (PowerShell)
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

---

## Usage

Launch the desktop application:

```bash
python main_v2.py
```

### Using Individual Modules Programmatically

The core utility scripts can also be imported or executed independently:

```python
# Password analysis
from password_checker import check_password
print(check_password("CyberSec@2026!"))  # Output: Strong Password

# File hashing
from hash_generator import generate_sha256
print(generate_sha256("requirements.txt"))

# Port scanning
from scanner import scan_common_ports
open_ports = scan_common_ports("scanme.nmap.org")
print(f"Open ports: {open_ports}")

# URL inspection
from checker import check_url
print(check_url("https://github.com"))  # Output: Safe
```

---

## Limitations

* **Port Scanning**: The included port scanner uses standard TCP connect probes (`socket.connect_ex`) against common service ports. It is not an asynchronous raw-packet engine like Nmap and should not be used for massive range sweeps.
* **JWT Inspector**: The JWT decoder decodes and displays token headers and claims for inspection; it does not verify cryptographic signatures against a secret key or public certificate.
* **URL Inspector**: Employs heuristic syntax and protocol analysis. It does not replace live threat intelligence feeds or sandboxed malware detestation.

---

## Security & Ethical Use Disclaimer

> **Important**: This toolkit is created strictly for educational, defensive, and authorized administrative testing purposes. 
> 
> Unauthorized scanning, reconnaissance, or testing against systems, networks, or domains without explicit, written permission from the owner is illegal and unethical. The author and contributors assume no liability for misuse or damage caused by this software. Always test responsibly against localhost, owned domains, or designated targets like `scanme.nmap.org`.

---

## Contributing

Contributions, bug reports, and enhancements are welcome:

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/improvement-name`).
3. Commit your changes with clear, descriptive messages (`git commit -m 'feat: add feature'`).
4. Push to your branch (`git push origin feature/improvement-name`).
5. Open a Pull Request.

---

## License

This project is open-source. Please consult repository tags or add a formal `LICENSE` file for distribution terms.
