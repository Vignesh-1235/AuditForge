"""
Parser Engine - Handles XML, JSON, CSV, TXT, LOG files
Extracts security findings from all evidence files.
"""

import os
import re
import csv
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional
from utils.logger import get_logger

logger = get_logger("parser_engine")

SEVERITY_KEYWORDS = {
    "critical": ["critical", "exploit", "rce", "remote code execution", "sql injection", "sqli",
                 "command injection", "auth bypass", "authentication bypass", "unauthenticated",
                 "anonymous login", "anonymous ftp", "default credentials", "no password",
                 "hydra", "brute force success"],
    "high": ["high", "csrf", "xss", "cross-site", "ssl 2.0", "ssl 3.0", "tls 1.0", "tls 1.1",
             "weak cipher", "rc4", "des", "3des", "null cipher", "export cipher",
             "self-signed", "expired certificate", "http (not https)", "cleartext",
             "smb signing disabled", "snmp", "default community", "outdated", "end-of-life",
             "windows 2008", "windows 2003", "windows xp", "eol", "vulnerability",
             "ftps/tls not detected", "no encryption", "open redirect", "missing header",
             "clickjacking", "x-frame-options", "content-security-policy missing"],
    "medium": ["medium", "information disclosure", "banner", "version disclosure",
               "directory listing", "nikto", "http methods", "trace", "put method",
               "weak password policy", "unnecessary service", "udp open"],
    "low": ["low", "informational", "note", "info"]
}


@dataclass
class Finding:
    severity: str          # critical / high / medium / low
    title: str
    host: str
    port: str
    service: str
    description: str
    evidence: str
    source_file: str
    recommendation: str = ""
    llm_analysis: str = ""


class ParserEngine:
    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        self.findings: List[Finding] = []

    def parse_all(self) -> List[Finding]:
        """Walk all files and dispatch to appropriate parser."""
        data_path = Path(self.data_dir)

        # Single file mode
        if data_path.is_file():
            self._dispatch_file(str(data_path))
        else:
            # Folder mode - walk recursively
            for root, dirs, files in os.walk(self.data_dir):
                dirs[:] = [d for d in dirs if not d.startswith('.')]
                for fname in files:
                    fpath = os.path.join(root, fname)
                    self._dispatch_file(fpath)

        self.findings = self._deduplicate(self.findings)
        logger.info(f"Parsed {len(self.findings)} unique findings from {self.data_dir}")
        return self.findings

    def _dispatch_file(self, fpath: str):
        """Dispatch a single file to the right parser."""
        ext = Path(fpath).suffix.lower()
        try:
            if ext == ".xml":
                self._parse_xml(fpath)
            elif ext == ".json":
                self._parse_json(fpath)
            elif ext == ".csv":
                self._parse_csv(fpath)
            else:
                self._parse_text(fpath)
        except Exception as e:
            logger.warning(f"Error parsing {fpath}: {e}")



    # ------------------------------------------------------------------ #
    #  XML Parser
    # ------------------------------------------------------------------ #
    def _parse_xml(self, fpath: str):
        logger.info(f"Parsing XML: {fpath}")
        try:
            tree = ET.parse(fpath)
            root = tree.getroot()
            xml_text = ET.tostring(root, encoding="unicode")
            # Extract findings from nmap XML format if present
            self._extract_from_text(fpath, xml_text)
        except ET.ParseError:
            # Fall back to text parsing
            self._parse_text(fpath)

    # ------------------------------------------------------------------ #
    #  JSON Parser
    # ------------------------------------------------------------------ #
    def _parse_json(self, fpath: str):
        logger.info(f"Parsing JSON: {fpath}")
        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
            try:
                data = json.load(f)
                text = json.dumps(data, indent=2)
                self._extract_from_text(fpath, text)
            except json.JSONDecodeError:
                f.seek(0)
                self._extract_from_text(fpath, f.read())

    # ------------------------------------------------------------------ #
    #  CSV Parser
    # ------------------------------------------------------------------ #
    def _parse_csv(self, fpath: str):
        logger.info(f"Parsing CSV: {fpath}")
        fname = Path(fpath).name.lower()

        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        # --- services CSV: detect risky open ports ---
        if "service" in fname or "services" in fname:
            risky_services = {
                "ftp": ("high", "FTP Service Exposed", "FTP transmits data in cleartext. Use SFTP or FTPS instead."),
                "telnet": ("critical", "Telnet Service Exposed", "Telnet is unencrypted. Replace with SSH immediately."),
                "smb": ("high", "SMB Service Exposed", "SMB exposure risks ransomware/lateral movement."),
                "rdp": ("high", "RDP Exposed", "RDP is a common attack vector for brute force and exploits."),
                "snmp": ("high", "SNMP Service Exposed", "SNMP with default community strings leaks network info."),
                "ms-sql": ("high", "MSSQL Exposed", "Database port exposed to network."),
                "mysql": ("high", "MySQL Exposed", "Database port exposed to network."),
                "db2": ("high", "DB2 Exposed", "Database port exposed to network."),
                "vnc": ("critical", "VNC Exposed", "VNC may allow unauthenticated remote desktop access."),
            }
            for row in rows:
                state = row.get("state", "").lower()
                if state not in ("open", "open|filtered"):
                    continue
                svc = row.get("name", "").lower()
                host = row.get("host", "")
                port = row.get("port", "")
                proto = row.get("proto", "")

                for keyword, (sev, title, rec) in risky_services.items():
                    if keyword in svc:
                        self.findings.append(Finding(
                            severity=sev,
                            title=title,
                            host=host,
                            port=port,
                            service=svc,
                            description=f"{title} detected on {host}:{port}/{proto}. Service: {svc}.",
                            evidence=f"Host: {host}, Port: {port}, Protocol: {proto}, Service: {svc}, State: {state}",
                            source_file=fpath,
                            recommendation=rec
                        ))

        # --- hosts CSV: detect EOL OS ---
        elif "host" in fname:
            eol_os = {
                "2003": "critical", "2008": "high", "xp": "critical",
                "vista": "high", "2000": "critical"
            }
            for row in rows:
                os_name = row.get("os_name", "") + " " + row.get("os_sp", "")
                host = row.get("address", "")
                for keyword, sev in eol_os.items():
                    if keyword in os_name.lower():
                        self.findings.append(Finding(
                            severity=sev,
                            title=f"End-of-Life OS Detected: {os_name.strip()}",
                            host=host,
                            port="",
                            service="OS",
                            description=f"Host {host} is running {os_name.strip()}, which is past end-of-life and no longer receives security patches.",
                            evidence=str(row),
                            source_file=fpath,
                            recommendation="Upgrade to a supported OS version immediately. EOL systems lack security patches and are high-risk targets."
                        ))

        # --- notes CSV: extract vulnerability notes ---
        elif "note" in fname:
            vuln_keywords = ["vuln", "exploit", "weak", "anonymous", "default", "no password",
                             "csrf", "xss", "injection", "disclosure", "misconfigur"]
            for row in rows:
                data_str = str(row.get("Data", "")) + str(row.get("Type", ""))
                data_lower = data_str.lower()
                for kw in vuln_keywords:
                    if kw in data_lower:
                        host = row.get("Host", "")
                        svc = row.get("Service", "")
                        port = row.get("Port", "")
                        sev = self._classify_severity(data_lower)
                        self.findings.append(Finding(
                            severity=sev,
                            title=f"Security Note: {row.get('Type', 'Vulnerability')} on {host}",
                            host=host,
                            port=port,
                            service=svc,
                            description=data_str[:500],
                            evidence=data_str[:1000],
                            source_file=fpath,
                        ))
                        break

    # ------------------------------------------------------------------ #
    #  TXT / LOG Parser
    # ------------------------------------------------------------------ #
    def _parse_text(self, fpath: str):
        logger.info(f"Parsing TEXT/LOG: {Path(fpath).name}")
        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        # Strip ANSI escape codes
        content = re.sub(r'\x1b\[[0-9;]*m', '', content)
        self._extract_from_text(fpath, content)

    # ------------------------------------------------------------------ #
    #  Core Extraction Logic
    # ------------------------------------------------------------------ #
    def _extract_from_text(self, fpath: str, content: str):
        """Extract structured findings from raw text content."""
        fname = Path(fpath).name.lower()
        fpath_lower = str(fpath).lower().replace("\\", "/")
        content_lower = content.lower()

        # in_path checks both filename and full path so single-file mode works
        def in_path(*keywords):
            return any(k in fpath_lower or k in fname for k in keywords)

        # Extract host IP from filename if present
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', fname)
        host = ip_match.group(1) if ip_match else self._extract_host(content)

        # Extract port from filename
        port_match = re.search(r'_(\d{2,5})_', fname)
        port = port_match.group(1) if port_match else ""

        # ---- Specific pattern matchers ----

        # 1. Anonymous FTP login
        if in_path("anonymous", "anon") or "anonymous" in content_lower:
            if "login successful" in content_lower or "230" in content or "anonymous" in content_lower:
                self.findings.append(Finding(
                    severity="critical",
                    title="Anonymous FTP Login Allowed",
                    host=host, port="21", service="ftp",
                    description=f"FTP server at {host} allows anonymous login without credentials, exposing files to any unauthenticated user.",
                    evidence=content[:800],
                    source_file=fpath,
                    recommendation="Disable anonymous FTP access. Require authentication for all FTP connections. Consider migrating to SFTP."
                ))

        # 2. Default/no-password admin login
        if in_path("admin_nopass") or "admin no" in content_lower:
            if "login successful" in content_lower or "230" in content or "331" in content:
                self.findings.append(Finding(
                    severity="critical",
                    title="Default Admin Credentials (No Password)",
                    host=host, port="21", service="ftp",
                    description=f"FTP server at {host} accepts admin login with no password.",
                    evidence=content[:800],
                    source_file=fpath,
                    recommendation="Immediately change default credentials. Enforce strong password policy on all services."
                ))

        # 3. Hydra brute force results
        if in_path("hydra"):
            for line in content.split("\n"):
                if "[21]" in line and "login:" in line.lower():
                    self.findings.append(Finding(
                        severity="critical",
                        title="FTP Credentials Found via Brute Force",
                        host=host, port="21", service="ftp",
                        description=f"Hydra brute force attack found valid FTP credentials on {host}.",
                        evidence=line.strip(),
                        source_file=fpath,
                        recommendation="Implement account lockout policies. Use fail2ban or similar intrusion prevention. Disable FTP and use SFTP."
                    ))

        # 4. FTPS/TLS not detected
        if "ftps/tls not detected" in content_lower or in_path("ftps"):
            self.findings.append(Finding(
                severity="high",
                title="FTP Without Encryption (No FTPS/TLS)",
                host=host, port="21", service="ftp",
                description=f"FTP server at {host} does not support FTPS/TLS. Data including credentials are transmitted in cleartext.",
                evidence=self._extract_snippet(content, "ftps", 300),
                source_file=fpath,
                recommendation="Enable FTPS (FTP over TLS). Configure the server to require encrypted connections only."
            ))

        # 5. SSL/TLS weak ciphers
        if in_path("ssl_ciphers", "ssl") or "ssl" in content_lower[:200]:
            weak_ciphers = ["rc4", "des", "3des", "null", "export", "anon", "tls 1.0", "tls 1.1",
                            "sslv2", "sslv3", "ssl2", "ssl3"]
            found_weak = [c for c in weak_ciphers if c in content_lower]
            if found_weak:
                self.findings.append(Finding(
                    severity="high",
                    title=f"Weak SSL/TLS Ciphers Detected",
                    host=host, port=port or "443", service="https",
                    description=f"Weak/deprecated ciphers found on {host}:{port or '443'}: {', '.join(found_weak)}. These ciphers are vulnerable to known attacks.",
                    evidence=self._extract_snippet(content, found_weak[0], 400),
                    source_file=fpath,
                    recommendation="Disable weak ciphers (RC4, DES, 3DES, NULL, EXPORT). Enforce TLS 1.2+ only. Use strong AEAD cipher suites (AES-GCM)."
                ))

        # 6. CSRF vulnerabilities
        if "csrf" in content_lower:
            self.findings.append(Finding(
                severity="high",
                title="CSRF Vulnerability Detected",
                host=host, port=port or "80", service="http",
                description=f"Cross-Site Request Forgery (CSRF) vulnerabilities found on web application at {host}:{port or '80'}. Forms lack anti-CSRF tokens.",
                evidence=self._extract_snippet(content, "csrf", 500),
                source_file=fpath,
                recommendation="Implement CSRF tokens on all state-changing forms. Use SameSite cookie attribute. Validate Origin/Referer headers."
            ))

        # 7. nmap vuln scan findings
        if in_path("nmap_vuln", "nmap") or "nmap" in content_lower[:100]:
            vuln_patterns = [
                (r"CVE-\d{4}-\d+", "critical", "Known CVE Detected"),
                (r"VULNERABLE", "high", "Nmap Vulnerability Confirmed"),
                (r"http-shellshock", "critical", "Shellshock Vulnerability"),
                (r"ms17-010", "critical", "EternalBlue (MS17-010) SMB Vulnerability"),
                (r"http-sql-injection", "critical", "SQL Injection Vulnerability"),
            ]
            for pattern, sev, title in vuln_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    self.findings.append(Finding(
                        severity=sev,
                        title=f"{title}: {', '.join(set(matches[:3]))}",
                        host=host, port=port or "80", service="http",
                        description=f"{title} found on {host}. Matches: {', '.join(set(matches[:5]))}",
                        evidence=self._extract_snippet(content, matches[0], 500),
                        source_file=fpath,
                        recommendation="Apply vendor patches immediately. Review affected services and restrict access."
                    ))

        # 8. Missing security headers
        if in_path("header") or "server:" in content_lower or "x-frame" in content_lower:
            missing_headers = []
            important_headers = {
                "x-frame-options": "Clickjacking protection missing",
                "content-security-policy": "CSP header missing - XSS risk",
                "x-content-type-options": "MIME sniffing protection missing",
                "strict-transport-security": "HSTS missing - downgrade attack risk",
                "x-xss-protection": "XSS protection header missing"
            }
            for header, desc in important_headers.items():
                if header not in content_lower:
                    missing_headers.append(desc)

            if len(missing_headers) >= 2:
                self.findings.append(Finding(
                    severity="medium",
                    title="Missing HTTP Security Headers",
                    host=host, port=port or "80", service="http",
                    description=f"Web server at {host} is missing important security headers: {'; '.join(missing_headers)}",
                    evidence=content[:600],
                    source_file=fpath,
                    recommendation="Configure all recommended security headers. Use tools like securityheaders.com to verify."
                ))

        # 9. SNMP detection
        if in_path("snmp") or "snmp" in content_lower:
            if "161" in content or "snmp" in fname:
                self.findings.append(Finding(
                    severity="high",
                    title="SNMP Service Detected",
                    host=host, port="161", service="snmp",
                    description=f"SNMP service detected on {host}:161. SNMP with default community strings (public/private) leaks full network topology and device configuration.",
                    evidence=content[:500],
                    source_file=fpath,
                    recommendation="Disable SNMPv1/v2c. Upgrade to SNMPv3 with authentication and encryption. Change default community strings."
                ))

        # 10. Nikto web vulnerability scanner findings
        if in_path("nikto") or "nikto" in content_lower[:200]:
            nikto_vulns = re.findall(r'\+ (.*?)(?:\n|$)', content)
            for finding in nikto_vulns[:10]:
                if len(finding) > 20 and any(k in finding.lower() for k in
                                              ["vuln", "dangerous", "exposed", "allow", "disclosure"]):
                    sev = self._classify_severity(finding.lower())
                    self.findings.append(Finding(
                        severity=sev,
                        title=f"Nikto Finding: {finding[:80]}",
                        host=host, port="80", service="http",
                        description=finding,
                        evidence=finding,
                        source_file=fpath,
                        recommendation="Review and remediate Nikto findings. Apply patches and disable unnecessary features."
                    ))

        # 11. WAF test findings
        if in_path("waf") or "waf" in content_lower[:200]:
            if "bypass" in content_lower or "not detected" in content_lower or "no waf" in content_lower:
                self.findings.append(Finding(
                    severity="high",
                    title="No Web Application Firewall (WAF) Detected",
                    host=host, port="80/443", service="http",
                    description=f"No WAF detected protecting the web application at {host}. The application is directly exposed to web attacks.",
                    evidence=content[:400],
                    source_file=fpath,
                    recommendation="Deploy a Web Application Firewall (WAF) in front of all web applications. Consider AWS WAF, Cloudflare, or ModSecurity."
                ))

        # 12. testssl findings
        if in_path("testssl") or "testssl" in content_lower[:200]:
            issues = []
            if "sweet32" in content_lower:
                issues.append("SWEET32 birthday attack (3DES)")
            if "beast" in content_lower:
                issues.append("BEAST attack vulnerability")
            if "poodle" in content_lower:
                issues.append("POODLE attack (SSLv3)")
            if "heartbleed" in content_lower:
                issues.append("Heartbleed vulnerability")
            if "robot" in content_lower:
                issues.append("ROBOT attack")
            if "lucky13" in content_lower:
                issues.append("Lucky13 vulnerability")
            if issues:
                self.findings.append(Finding(
                    severity="critical",
                    title=f"SSL/TLS Attack Vulnerabilities: {', '.join(issues[:2])}",
                    host=host, port=port or "443", service="https",
                    description=f"TLS vulnerability assessment found: {', '.join(issues)} on {host}",
                    evidence=content[:600],
                    source_file=fpath,
                    recommendation="Update SSL/TLS configuration. Disable vulnerable protocol versions. Apply latest patches."
                ))

        # 13. DB2 version disclosure
        if in_path("db2") or "db2" in content_lower[:200]:
            self.findings.append(Finding(
                severity="high",
                title="Database Service Exposed (DB2)",
                host=host, port="50000", service="db2",
                description=f"IBM DB2 database service detected on {host}:50000. Database ports should not be exposed to the network.",
                evidence=content[:400],
                source_file=fpath,
                recommendation="Restrict DB2 port 50000 using firewall rules. Only application servers should access database ports."
            ))

        # 14. FileZilla old version
        if "filezilla" in content_lower and "0.9" in content:
            self.findings.append(Finding(
                severity="high",
                title="Outdated FileZilla Server (EOL Version 0.9.x)",
                host=host, port="21", service="ftp",
                description=f"FileZilla Server 0.9.x detected on {host}. This version is end-of-life and has known vulnerabilities.",
                evidence=self._extract_snippet(content, "filezilla", 300),
                source_file=fpath,
                recommendation="Upgrade FileZilla Server to the latest stable version. Consider migrating to SFTP (OpenSSH)."
            ))

        # 15. WPScan findings
        if in_path("wpscan") or "wpscan" in content_lower[:200]:
            if "vulnerabilit" in content_lower:
                self.findings.append(Finding(
                    severity="high",
                    title="WordPress Vulnerabilities Detected",
                    host=host, port="80/443", service="http/wordpress",
                    description="WPScan detected vulnerabilities in the WordPress installation.",
                    evidence=content[:800],
                    source_file=fpath,
                    recommendation="Update WordPress core, themes, and plugins. Remove unused plugins. Implement a security plugin like Wordfence."
                ))


        # 16. Domain Recon — subdomain enumeration exposure
        if in_path("domain_recon", "theharvester", "harvester", "dns_all", "dns"):
            # Exposed subdomains
            subdomains = re.findall(r'([a-zA-Z0-9\-]+\.[a-zA-Z0-9\-]+\.[a-zA-Z]{2,})', content)
            sensitive = [s for s in subdomains if any(k in s.lower() for k in
                ["ftp", "vpn", "mail", "admin", "dev", "staging", "test", "bugzilla",
                 "git", "svn", "internal", "corp", "backup", "db", "database", "api",
                 "mdm", "plm", "tfs", "keys", "cloud", "support", "gate", "isl"])]
            if sensitive:
                unique_subs = list(dict.fromkeys(sensitive))[:10]
                self.findings.append(Finding(
                    severity="medium",
                    title="Sensitive Subdomains Exposed via DNS Enumeration",
                    host=host or "DNS",
                    port="53", service="dns",
                    description=f"DNS enumeration revealed {len(unique_subs)} potentially sensitive subdomains including: {', '.join(unique_subs[:5])}. These may expose internal services to attackers.",
                    evidence="\n".join(unique_subs),
                    source_file=fpath,
                    recommendation="1. Review all exposed subdomains and remove unnecessary ones. 2. Implement DNS zone transfer restrictions. 3. Ensure internal services are not accessible from the internet."
                ))

            # FTP subdomain exposure
            ftp_subs = [s for s in subdomains if "ftp" in s.lower()]
            if ftp_subs:
                self.findings.append(Finding(
                    severity="high",
                    title="FTP Service Exposed via Public DNS",
                    host=ftp_subs[0], port="21", service="ftp",
                    description=f"Public DNS record reveals FTP service: {', '.join(ftp_subs)}. FTP transmits credentials in cleartext.",
                    evidence="\n".join(ftp_subs),
                    source_file=fpath,
                    recommendation="1. Disable FTP and migrate to SFTP. 2. Remove public DNS records for FTP services. 3. Block port 21 at the perimeter firewall."
                ))

        # 16b. domain_recon.log — orchestration log summary finding
        if in_path("domain_recon") and "domain reconnaissance" in content_lower:
            domain_match = re.search(r'for ([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})', content)
            domain = domain_match.group(1) if domain_match else "target domain"
            self.findings.append(Finding(
                severity="medium",
                title=f"Domain Reconnaissance Performed Against {domain}",
                host=host or "OSINT",
                port="—", service="osint/recon",
                description=f"Automated domain reconnaissance was conducted against {domain} including WHOIS lookup, DNS enumeration, subdomain discovery, email harvesting, Shodan search, and Wayback Machine analysis. This indicates the organisation's external footprint has been mapped.",
                evidence=content[:600],
                source_file=fpath,
                recommendation="1. Monitor for reconnaissance activity using threat intelligence feeds. 2. Implement rate limiting on DNS queries. 3. Review and minimise publicly exposed infrastructure. 4. Enable WHOIS privacy protection."
            ))

        # 17. theHarvester — email/host harvesting
        if in_path("theharvester", "harvester"):
            emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', content)
            real_emails = [e for e in emails if "example" not in e and "test" not in e and "redacted" not in e.lower()]
            if real_emails:
                unique_emails = list(dict.fromkeys(real_emails))[:10]
                self.findings.append(Finding(
                    severity="medium",
                    title="Employee Email Addresses Harvested (Information Disclosure)",
                    host=host or "OSINT",
                    port="—", service="osint",
                    description=f"theHarvester discovered {len(unique_emails)} employee email addresses publicly exposed. These can be used for phishing and credential stuffing attacks.",
                    evidence="\n".join(unique_emails),
                    source_file=fpath,
                    recommendation="1. Implement email filtering and anti-phishing controls. 2. Enable MFA on all email accounts. 3. Train staff on phishing awareness."
                ))

        # 18. Wayback Machine — sensitive URLs exposed
        if in_path("wayback"):
            sensitive_paths = re.findall(r'https?://[^\s\[\]"]+', content)
            risky = [u for u in sensitive_paths if any(k in u.lower() for k in
                [".php", ".asp", ".aspx", "admin", "login", "config", "backup",
                 ".sql", ".bak", ".env", "upload", "api/", "debug", "test", "dev"])]
            if risky:
                unique_risky = list(dict.fromkeys(risky))[:8]
                self.findings.append(Finding(
                    severity="medium",
                    title="Sensitive URLs Exposed in Wayback Machine Archive",
                    host=host or "Web",
                    port="80/443", service="http",
                    description=f"Wayback Machine archives reveal {len(unique_risky)} historically exposed sensitive URLs that may disclose admin panels, config files, or backup data.",
                    evidence="\n".join(unique_risky[:5]),
                    source_file=fpath,
                    recommendation="1. Review and remove sensitive content from web archive if possible. 2. Ensure old admin/config paths are disabled. 3. Implement proper access controls on all sensitive endpoints."
                ))

        # 19. WHOIS — registration info exposure
        if in_path("whois"):
            if "registrant" in content_lower or "admin email" in content_lower or "tech email" in content_lower:
                self.findings.append(Finding(
                    severity="low",
                    title="WHOIS Registration Data Publicly Accessible",
                    host=host or "DNS",
                    port="43", service="whois",
                    description="WHOIS lookup reveals organisation registration details including contact names, email addresses, and registrar information that could aid social engineering attacks.",
                    evidence=content[:400],
                    source_file=fpath,
                    recommendation="1. Enable WHOIS privacy protection with your registrar. 2. Use a generic administrative contact email. 3. Avoid exposing personal staff details in registration records."
                ))

        # 20. SPF/DMARC misconfig in DNS TXT records
        if in_path("dns_all", "dns") or "spf" in content_lower[:500]:
            if "v=spf1" in content_lower:
                if "-all" not in content_lower and "~all" not in content_lower:
                    self.findings.append(Finding(
                        severity="medium",
                        title="SPF Record Missing Hard Fail (-all) — Email Spoofing Risk",
                        host=host or "DNS",
                        port="53", service="dns/email",
                        description="The SPF record does not use a hard fail (-all) directive. This allows unauthorised senders to potentially spoof the organisation's email domain.",
                        evidence=self._extract_snippet(content, "spf", 300),
                        source_file=fpath,
                        recommendation="1. Update SPF record to end with -all instead of ~all or ?all. 2. Implement DMARC policy with p=reject. 3. Enable DKIM signing on all outbound mail."
                    ))
            if "v=spf1" not in content_lower and in_path("dns_all", "dns"):
                pass  # no SPF at all — skip, too noisy without confirmation



        # 21. SMB Enumeration — open/filtered ports = attack surface
        if in_path("smb_enum"):
            hosts_smb = re.findall(r'Nmap scan report for (\d+\.\d+\.\d+\.\d+)', content)
            open_smb  = re.findall(r'(\d+\.\d+\.\d+\.\d+).*?(?=Nmap scan|$)', content, re.DOTALL)
            # Find hosts with open or filtered SMB
            smb_exposed = []
            for block in re.split(r'Nmap scan report for ', content):
                ip_m = re.match(r'(\d+\.\d+\.\d+\.\d+)', block)
                if ip_m and ('open' in block or 'filtered' in block) and ('445' in block or '139' in block):
                    smb_exposed.append(ip_m.group(1))
            if smb_exposed:
                for smb_host in smb_exposed[:5]:
                    self.findings.append(Finding(
                        severity="high",
                        title=f"SMB Service Exposed on {smb_host} (Ports 139/445)",
                        host=smb_host, port="445", service="smb",
                        description=f"SMB ports 139/445 are open or filtered on {smb_host}. SMB is commonly exploited via EternalBlue, brute force, and relay attacks. Unpatched SMB services allow remote code execution.",
                        evidence=self._extract_snippet(content, smb_host, 400),
                        source_file=fpath,
                        recommendation="1. Disable SMBv1 immediately. 2. Ensure MS17-010 patch is applied. 3. Block SMB (139/445) at perimeter firewall. 4. Enable SMB signing to prevent relay attacks."
                    ))
            elif hosts_smb:
                # Even closed/filtered = enumerated = recon finding
                self.findings.append(Finding(
                    severity="low",
                    title="SMB Service Enumeration Performed",
                    host=hosts_smb[0] if hosts_smb else host,
                    port="445", service="smb",
                    description=f"SMB enumeration was performed across {len(hosts_smb)} hosts. SMB ports were found closed or filtered, reducing attack surface. However, enumeration confirms SMB is in scope.",
                    evidence=content[:400],
                    source_file=fpath,
                    recommendation="1. Ensure SMBv1 is disabled on all hosts. 2. Maintain firewall rules blocking SMB from external access. 3. Monitor SMB traffic for lateral movement."
                ))

        # 22. SSH Enumeration — failed/error = misconfigured SSH scripts
        if in_path("ssh_enum"):
            if "failed to initialize" in content_lower or "quitting" in content_lower:
                self.findings.append(Finding(
                    severity="medium",
                    title="SSH Script Engine Failure — SSH Security Audit Incomplete",
                    host=host or "Multiple Hosts", port="22", service="ssh",
                    description="Nmap SSH enumeration scripts failed to initialise during the assessment. This means SSH algorithm and configuration weaknesses may not have been fully tested. SSH weak algorithms (diffie-hellman-group1, arcfour) allow downgrade attacks.",
                    evidence=content[:400],
                    source_file=fpath,
                    recommendation="1. Manually audit SSH configuration on all servers (sshd_config). 2. Disable weak algorithms: arcfour, CBC modes, diffie-hellman-group1. 3. Enforce key-based authentication and disable root login. 4. Use ssh-audit tool for comprehensive SSH assessment."
                ))
            ssh_hosts = re.findall(r'Nmap scan report for (\d+\.\d+\.\d+\.\d+)', content)
            open_ssh  = [b for b in re.split(r'Nmap scan report for ', content)
                         if '22/tcp' in b and 'open' in b]
            for block in open_ssh[:3]:
                ip_m = re.match(r'(\d+\.\d+\.\d+\.\d+)', block)
                if ip_m:
                    self.findings.append(Finding(
                        severity="medium",
                        title=f"SSH Service Open on {ip_m.group(1)} — Requires Hardening Review",
                        host=ip_m.group(1), port="22", service="ssh",
                        description=f"SSH port 22 is open on {ip_m.group(1)}. Without algorithm audit (which failed), weak ciphers and MACs may be enabled. SSH is a high-value target for brute force and credential stuffing.",
                        evidence=block[:300],
                        source_file=fpath,
                        recommendation="1. Run ssh-audit against this host. 2. Disable password authentication, use key-based only. 3. Restrict SSH access by source IP. 4. Change default port 22 to reduce automated scanning noise."
                    ))

        # 23. HTTP Enum — open HTTP/HTTPS ports + risky methods
        if in_path("http_enum"):
            risky_method_hosts = []
            open_http_hosts    = []
            for block in re.split(r'Nmap scan report for ', content):
                ip_m = re.match(r'(\d+\.\d+\.\d+\.\d+)', block)
                if not ip_m: continue
                bhost = ip_m.group(1)
                if 'potentially risky methods' in block.lower() or 'put' in block.lower() or 'delete' in block.lower():
                    risky_method_hosts.append(bhost)
                if ('80/tcp' in block or '443/tcp' in block or '8080/tcp' in block) and 'open' in block:
                    open_http_hosts.append(bhost)

            for rhost in risky_method_hosts[:5]:
                self.findings.append(Finding(
                    severity="high",
                    title=f"Risky HTTP Methods Enabled on {rhost} (PUT/DELETE)",
                    host=rhost, port="80/443", service="http",
                    description=f"HTTP server on {rhost} supports potentially dangerous methods such as PUT or DELETE. These can allow attackers to upload malicious files or delete content on the server.",
                    evidence=self._extract_snippet(content, rhost, 400),
                    source_file=fpath,
                    recommendation="1. Disable HTTP methods PUT, DELETE, TRACE, OPTIONS in web server config. 2. Restrict allowed methods to GET, POST, HEAD only. 3. Implement WAF rules to block dangerous HTTP methods."
                ))
            for ohost in [h for h in open_http_hosts if h not in risky_method_hosts][:3]:
                self.findings.append(Finding(
                    severity="medium",
                    title=f"HTTP/HTTPS Service Exposed on {ohost}",
                    host=ohost, port="80/443", service="http",
                    description=f"HTTP/HTTPS service is open on {ohost}. Web services are primary attack vectors for injection, authentication bypass, and information disclosure vulnerabilities.",
                    evidence=self._extract_snippet(content, ohost, 400),
                    source_file=fpath,
                    recommendation="1. Ensure all web services require authentication where applicable. 2. Implement HTTPS with valid certificates. 3. Deploy a WAF. 4. Review HTTP response headers for missing security controls."
                ))

        # 24. Security Headers — "Not found" = missing header vulnerabilities
        if in_path("security_headers"):
            hosts_missing = {}
            current = None
            for line in content.split("\n"):
                m = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if m: current = m.group(1)
                if current and "not found" in line.lower():
                    hdr = line.split(":")[0].strip()
                    if current not in hosts_missing:
                        hosts_missing[current] = []
                    if hdr and hdr not in hosts_missing[current]:
                        hosts_missing[current][len(hosts_missing[current]):] = [hdr]
            for sh, missing in list(hosts_missing.items())[:8]:
                if missing:
                    self.findings.append(Finding(
                        severity="medium",
                        title=f"Missing Security Headers on {sh}: {', '.join(missing[:3])}",
                        host=sh, port="80/443", service="http",
                        description=f"Security header analysis on {sh} found {len(missing)} missing HTTP security headers: {', '.join(missing)}. Missing headers expose users to clickjacking, XSS, MIME sniffing and other attacks.",
                        evidence=self._extract_snippet(content, sh, 400),
                        source_file=fpath,
                        recommendation="1. Add X-Frame-Options: DENY. 2. Add X-Content-Type-Options: nosniff. 3. Add Strict-Transport-Security with max-age. 4. Implement Content-Security-Policy. 5. Add X-XSS-Protection: 1; mode=block."
                    ))

        # 25. SSL Info — self-signed, wildcard, or expired certs
        if in_path("ssl_info"):
            if "no tls detected" in content_lower:
                no_tls_hosts = re.findall(r'No TLS detected on (\d+\.\d+\.\d+\.\d+:\d+)', content)
                for nt in no_tls_hosts[:5]:
                    h = nt.split(":")[0]
                    self.findings.append(Finding(
                        severity="high",
                        title=f"No TLS/SSL on {nt} — Cleartext Communication",
                        host=h, port=nt.split(":")[1] if ":" in nt else "80", service="http",
                        description=f"No TLS encryption detected on {nt}. All data transmitted to this service — including credentials and session tokens — is sent in cleartext and can be intercepted.",
                        evidence=self._extract_snippet(content, nt.split(":")[0], 300),
                        source_file=fpath,
                        recommendation="1. Deploy a valid TLS certificate immediately. 2. Redirect all HTTP traffic to HTTPS. 3. Implement HSTS to prevent downgrade attacks."
                    ))
            # Wildcard cert
            if "cn=*." in content_lower:
                wc_hosts = re.findall(r'(\d+\.\d+\.\d+\.\d+)', content)
                self.findings.append(Finding(
                    severity="medium",
                    title="Wildcard TLS Certificate in Use — Broad Attack Surface",
                    host=wc_hosts[0] if wc_hosts else host,
                    port="443", service="https",
                    description="A wildcard TLS certificate (CN=*.) is in use. If the private key is compromised, all subdomains covered by the wildcard are affected. Wildcard certs also make revocation impractical.",
                    evidence=self._extract_snippet(content, "CN=*", 400),
                    source_file=fpath,
                    recommendation="1. Replace wildcard certificate with individual per-domain certificates. 2. Store private key in an HSM. 3. Implement certificate transparency monitoring."
                ))

        # 26. API Endpoints — discovered endpoints + error codes
        if in_path("api_endpoint"):
            found_apis = []
            for line in content.split("\n"):
                if re.search(r'(200|301|302|401|403)', line) and "/" in line:
                    ep = re.search(r'(/[a-zA-Z0-9/_\-\.]+)', line)
                    if ep: found_apis.append(ep.group(1))
            if found_apis:
                self.findings.append(Finding(
                    severity="medium",
                    title="API Endpoints Discovered — Unauthenticated Access Possible",
                    host=host, port="80/443", service="http/api",
                    description=f"API endpoint discovery found {len(found_apis)} accessible endpoints: {', '.join(found_apis[:5])}. Exposed API endpoints may allow unauthenticated data access or function abuse.",
                    evidence="\n".join(found_apis[:10]),
                    source_file=fpath,
                    recommendation="1. Implement authentication on all API endpoints. 2. Use API gateway with rate limiting. 3. Remove or restrict undocumented endpoints. 4. Conduct API-specific security testing."
                ))
            else:
                # Even 404s on sensitive paths = recon
                self.findings.append(Finding(
                    severity="low",
                    title="API Endpoint Enumeration Performed — Attack Surface Mapped",
                    host=host, port="80/443", service="http/api",
                    description="Automated API endpoint discovery was performed against web services. Common API paths were probed. Even 404 responses confirm the web server is reachable and enumerate technology stack.",
                    evidence=content[:400],
                    source_file=fpath,
                    recommendation="1. Implement API rate limiting to slow enumeration. 2. Return consistent error responses to prevent information leakage. 3. Implement an API gateway. 4. Monitor for automated scanning patterns."
                ))

        # 27. Directories — wildcard redirect / enumeration errors
        if in_path("directories", "ffuf"):
            if "wildcard" in content_lower or "status code that matches" in content_lower:
                wc_hosts = re.findall(r'http[s]?://(\d+\.\d+\.\d+\.\d+)', content)
                for wh in wc_hosts[:3]:
                    self.findings.append(Finding(
                        severity="medium",
                        title=f"Web Application Wildcard Response on {wh} — Directory Bruteforce Hindered",
                        host=wh, port="80/443", service="http",
                        description=f"The web application on {wh} returns the same status code for non-existent URLs as existing ones, indicating a wildcard/catch-all route. This may indicate a misconfigured server or intentional obfuscation.",
                        evidence=self._extract_snippet(content, wh, 400),
                        source_file=fpath,
                        recommendation="1. Investigate the wildcard routing — ensure 404 responses return proper HTTP 404 status. 2. Review application routing configuration. 3. Check for open redirect vulnerabilities."
                    ))
            elif "status: 200" in content_lower or "status: 301" in content_lower or "status: 403" in content_lower:
                found_hosts = re.findall(r'http[s]?://(\d+\.\d+\.\d+\.\d+)', content)
                for fh in (found_hosts or [host])[:3]:
                    self.findings.append(Finding(
                        severity="medium",
                        title=f"Hidden Directories/Files Discovered on {fh}",
                        host=fh, port="80/443", service="http",
                        description=f"Directory and file enumeration on {fh} discovered accessible paths. Hidden directories can expose admin panels, backup files, configuration files, or sensitive data.",
                        evidence=content[:500],
                        source_file=fpath,
                        recommendation="1. Remove or restrict access to sensitive directories. 2. Implement authentication on admin paths. 3. Configure web server to return 404 for unlisted paths. 4. Regular review of publicly accessible endpoints."
                    ))

        # 28. Web enum log — Nikto timeout = incomplete scan + Gobuster ran
        if in_path("web_enum") and "web_enum.log" in fpath.lower():
            nikto_timeout_hosts = re.findall(r'Enumerating https?://(\d+\.\d+\.\d+\.\d+)', content)
            if nikto_timeout_hosts:
                self.findings.append(Finding(
                    severity="medium",
                    title="Web Enumeration Incomplete — Nikto Scan Timed Out on Multiple Hosts",
                    host=nikto_timeout_hosts[0] if nikto_timeout_hosts else host,
                    port="80/443", service="http",
                    description=f"Automated web enumeration was performed against {len(nikto_timeout_hosts)} web services. Nikto scans timed out on multiple targets, meaning vulnerabilities may remain undetected. Gobuster directory enumeration completed.",
                    evidence=content[:600],
                    source_file=fpath,
                    recommendation="1. Re-run Nikto manually with extended timeout: nikto -h <target> -timeout 3600. 2. Conduct manual web application testing on all targets. 3. Use Burp Suite for comprehensive web assessment."
                ))

        # 29. FTP not connected — still indicates FTP service probed
        if in_path("ftp") and ("not connected" in content_lower or "nmap scan report" in content_lower):
            if "not connected" in content_lower:
                self.findings.append(Finding(
                    severity="high",
                    title=f"FTP Service Probe — Connection Attempt Recorded on {host}",
                    host=host, port="21", service="ftp",
                    description=f"An FTP connection attempt was made to {host} but failed (Not Connected). FTP service is in scope and was targeted. FTP transmits all data including credentials in cleartext.",
                    evidence=content[:300],
                    source_file=fpath,
                    recommendation="1. If FTP is not needed, disable it immediately. 2. If required, migrate to SFTP (SSH file transfer). 3. Block port 21 at the perimeter firewall. 4. Use FTP over TLS (FTPS) as minimum."
                ))
            elif "21/tcp open" in content_lower:
                self.findings.append(Finding(
                    severity="critical",
                    title=f"FTP Service Open on {host} Port 21",
                    host=host, port="21", service="ftp",
                    description=f"Nmap scan confirms FTP port 21 is open on {host}. FTP is an inherently insecure protocol that transmits credentials and data in cleartext. It is commonly exploited for unauthorised file access.",
                    evidence=content[:400],
                    source_file=fpath,
                    recommendation="1. Disable FTP service immediately. 2. Migrate to SFTP. 3. Block port 21 at the firewall. 4. Audit FTP logs for unauthorised access attempts."
                ))

        # 30. Hydra FTP — even 0 valid passwords = cleartext protocol used
        if in_path("hydra") and "ftp" in content_lower:
            hydra_host = re.search(r'ftp://(\d+\.\d+\.\d+\.\d+)', content)
            h = hydra_host.group(1) if hydra_host else host
            if "0 valid password" in content_lower or "1 of 1 target completed" in content_lower:
                self.findings.append(Finding(
                    severity="high",
                    title=f"FTP Brute-Force Attack Attempted on {h} — Cleartext Protocol Risk",
                    host=h, port="21", service="ftp",
                    description=f"Hydra brute-force tool was used against FTP on {h}. Although no valid passwords were found, the fact that FTP is running means credentials could be captured via network sniffing. FTP provides no protection against credential interception.",
                    evidence=content,
                    source_file=fpath,
                    recommendation="1. Disable FTP and replace with SFTP. 2. Implement account lockout after failed login attempts. 3. Monitor FTP logs for brute-force patterns. 4. Block FTP from all untrusted network segments."
                ))

        # 31. IP Analysis log — large IP range = broad attack surface
        if in_path("ip_analysis") and "asn lookup" in content_lower:
            ips = re.findall(r'ASN lookup for (\d+\.\d+\.\d+\.\d+)', content)
            if ips:
                self.findings.append(Finding(
                    severity="medium",
                    title=f"Large IP Range in Scope — {len(ips)} Hosts Analysed",
                    host=ips[0], port="—", service="network",
                    description=f"IP range analysis was performed across {len(ips)} hosts. A large number of in-scope hosts increases the attack surface and the potential for unpatched or unmonitored systems.",
                    evidence=f"Hosts analysed: {', '.join(ips[:10])}{'...' if len(ips)>10 else ''}",
                    source_file=fpath,
                    recommendation="1. Maintain an up-to-date asset inventory. 2. Ensure all hosts receive security patches. 3. Decommission unused hosts. 4. Implement network segmentation to limit lateral movement."
                ))

        # 32. Traceroute — network path exposure
        if in_path("traceroute"):
            hops = re.findall(r'(\d+\.\d+\.\d+\.\d+)', content)
            internal_hops = [h for h in hops if h.startswith(('10.','172.','192.168.'))]
            if internal_hops:
                unique_internal = list(dict.fromkeys(internal_hops))[:8]
                self.findings.append(Finding(
                    severity="low",
                    title="Internal Network Topology Exposed via Traceroute",
                    host=unique_internal[0], port="—", service="network",
                    description=f"Traceroute reveals {len(unique_internal)} internal network hops including: {', '.join(unique_internal[:5])}. Internal routing information aids attackers in network mapping and identifying gateway/router targets.",
                    evidence="\n".join(unique_internal),
                    source_file=fpath,
                    recommendation="1. Configure routers to not respond to ICMP TTL-exceeded messages. 2. Implement ICMP rate limiting. 3. Restrict traceroute capability from external networks."
                ))

        # 33. Reverse DNS — no PTR = missing DNS hygiene
        if in_path("reverse_dns"):
            no_ptr = re.findall(r'(\d+\.\d+\.\d+\.\d+) -> No reverse DNS', content)
            dns_errors = re.findall(r'(\d+\.\d+\.\d+\.\d+) -> .*error.*', content, re.IGNORECASE)
            if no_ptr:
                self.findings.append(Finding(
                    severity="low",
                    title=f"Missing Reverse DNS (PTR) Records — {len(no_ptr)} Hosts",
                    host=no_ptr[0], port="53", service="dns",
                    description=f"{len(no_ptr)} hosts have no reverse DNS PTR records. Missing PTR records indicate poor DNS hygiene, can cause issues with email deliverability, and make it harder to track malicious activity in logs.",
                    evidence=f"Hosts without PTR: {', '.join(no_ptr[:8])}",
                    source_file=fpath,
                    recommendation="1. Create PTR records for all in-scope IP addresses. 2. Ensure forward and reverse DNS records are consistent. 3. Implement DNS monitoring for changes."
                ))

        # 34. Geolocation — hosts in unexpected countries
        if in_path("geolocation"):
            countries = re.findall(r'"country":"([^"]+)"', content)
            isps      = re.findall(r'"isp":"([^"]+)"', content)
            ips_geo   = re.findall(r'"query":"(\d+\.\d+\.\d+\.\d+)"', content)
            if countries and ips_geo:
                unique_countries = list(dict.fromkeys(countries))
                self.findings.append(Finding(
                    severity="low",
                    title=f"Geolocation Data Exposed — Hosts Mapped to {', '.join(unique_countries[:3])}",
                    host=ips_geo[0], port="—", service="network",
                    description=f"Geolocation analysis mapped {len(ips_geo)} hosts to physical locations ({', '.join(unique_countries[:3])}). Geolocation data can be used to identify data residency risks, compliance issues, or unexpected hosting locations.",
                    evidence=f"IPs mapped: {', '.join(ips_geo[:5])} | Countries: {', '.join(unique_countries)}",
                    source_file=fpath,
                    recommendation="1. Review if hosting locations comply with data residency requirements. 2. Verify no systems are unexpectedly hosted in high-risk jurisdictions. 3. Implement geo-based access controls where required."
                ))

        # 35. BGP/ASN — organisation's IP range publicly visible
        if in_path("bgp"):
            asns = re.findall(r'"asn":(\d+)', content)
            prefixes = re.findall(r'"prefix":"([^"]+)"', content)
            if asns or prefixes:
                self.findings.append(Finding(
                    severity="low",
                    title="BGP Routing Information Publicly Accessible",
                    host=host or "Network", port="179", service="bgp",
                    description=f"BGP routing data reveals organisation IP prefixes and ASN information: {', '.join(list(dict.fromkeys(prefixes))[:3])}. This information aids attackers in mapping the organisation's complete internet presence.",
                    evidence=content[:400],
                    source_file=fpath,
                    recommendation="1. Minimise publicly exposed IP ranges where possible. 2. Implement BGP route filtering. 3. Monitor BGP for route hijacking. 4. Use RPKI to validate BGP route origins."
                ))

        # 36. IP list — attack surface scope
        if in_path("ip_list") and not in_path("ip_analysis"):
            ips_listed = re.findall(r'(\d+\.\d+\.\d+\.\d+)', content)
            if len(ips_listed) > 5:
                self.findings.append(Finding(
                    severity="low",
                    title=f"Attack Surface: {len(ips_listed)} In-Scope IP Addresses Identified",
                    host=ips_listed[0], port="—", service="network",
                    description=f"A list of {len(ips_listed)} in-scope IP addresses was identified: {', '.join(ips_listed[:8])}. Each live host represents an entry point that requires security validation.",
                    evidence="\n".join(ips_listed[:15]),
                    source_file=fpath,
                    recommendation="1. Ensure all listed hosts are covered by vulnerability scanning. 2. Decommission any hosts not in active use. 3. Document purpose and owner of each in-scope system."
                ))

        # 37. Search engine recon — Google dork queries = information exposure risk
        if in_path("search_engine"):
            dorks = re.findall(r'site:[^\s]+', content)
            if dorks:
                self.findings.append(Finding(
                    severity="medium",
                    title="Google Dork Queries Performed — Sensitive File/Path Exposure Risk",
                    host=host or "OSINT", port="—", service="osint",
                    description=f"Search engine reconnaissance was performed using {len(dorks)} Google dork queries targeting sensitive file types (PDF, DOC, XLS) and paths (admin, login, config). Indexed sensitive files may be publicly accessible.",
                    evidence="\n".join(dorks[:8]),
                    source_file=fpath,
                    recommendation="1. Review Google-indexed content for sensitive documents. 2. Submit removal requests for sensitive pages via Google Search Console. 3. Implement robots.txt to prevent indexing of sensitive paths. 4. Remove sensitive files from web-accessible directories."
                ))

        # 38. SSL Ciphers — open port only = service confirmed
        if in_path("ssl_ciphers") and "open" in content_lower and not any(
            kw in content_lower for kw in ["rc4","des","null","export","tls 1.0","sslv3","weak"]):
            port_m = re.search(r'(\d+)/tcp open', content)
            p = port_m.group(1) if port_m else ("443" if "https" in fpath.lower() else "80")
            self.findings.append(Finding(
                severity="medium",
                title=f"SSL/TLS Service Confirmed Open on {host}:{p} — Full Cipher Audit Required",
                host=host, port=p, service="https",
                description=f"SSL/TLS service is confirmed running on {host}:{p}. Automated weak cipher detection did not trigger, but manual cipher suite review is recommended as automated tools may miss non-standard configurations.",
                evidence=content[:300],
                source_file=fpath,
                recommendation="1. Run testssl.sh or sslscan for comprehensive cipher review. 2. Disable TLS 1.0 and 1.1. 3. Disable weak ciphers (RC4, DES, EXPORT). 4. Enable HSTS. 5. Implement certificate pinning for critical services."
            ))

        # 39. FTP anon port scan (Nmap) — port open = critical
        if in_path("ftp") and in_path("anon") and "21/tcp open" in content_lower:
            self.findings.append(Finding(
                severity="critical",
                title=f"FTP Anonymous Login Confirmed Open on {host}:21",
                host=host, port="21", service="ftp",
                description=f"Nmap scan confirms FTP port 21 is open on {host}. Combined with anonymous FTP test evidence, this confirms unauthenticated access to FTP service. Anonymous FTP allows any user to download/upload files without credentials.",
                evidence=content,
                source_file=fpath,
                recommendation="1. Disable anonymous FTP login immediately. 2. If FTP is required, restrict to named accounts with strong passwords. 3. Migrate to SFTP. 4. Monitor FTP logs for unauthorised access."
            ))


        # 40. Shodan — API not configured = still attempted intel gathering
        if in_path("shodan"):
            self.findings.append(Finding(
                severity="low",
                title="Shodan Reconnaissance Attempted — External Exposure Intelligence Gathering",
                host=host or "OSINT", port="—", service="osint",
                description="Shodan reconnaissance was attempted against the target domain. Even without API key results, Shodan indexing means the organisation's internet-facing services may be publicly catalogued including open ports, banners, and vulnerabilities.",
                evidence=content.strip() or "Shodan API key not configured",
                source_file=fpath,
                recommendation="1. Search Shodan manually for your organisation's IP ranges to understand exposure. 2. Review and minimise internet-facing services. 3. Ensure all exposed services are patched and hardened. 4. Set up Shodan monitoring alerts for your IP ranges."
            ))

        # 41. ASN — RIPE/ARIN data = organisation network ownership exposed
        if in_path("asn") and ("ripe" in content_lower or "arin" in content_lower or "inetnum" in content_lower or "netname" in content_lower or "redacted" in content_lower):
            self.findings.append(Finding(
                severity="low",
                title="ASN and Network Ownership Data Publicly Accessible via RIPE/ARIN",
                host=host or "Network", port="—", service="network",
                description="ASN lookup retrieved network ownership information from RIPE/ARIN databases. This data reveals the organisation's IP ranges, network names, and administrative contacts — all valuable for targeted attacks.",
                evidence=content[:500],
                source_file=fpath,
                recommendation="1. Review RIPE/ARIN records for accuracy and minimise exposed contact details. 2. Enable WHOIS privacy where possible. 3. Use generic NOC/abuse contacts instead of personal staff details."
            ))

        # 42. IP list file — plain list = scope document
        if in_path("ip_list"):
            ips_in_list = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', content)
            if ips_in_list:
                self.findings.append(Finding(
                    severity="low",
                    title=f"Target IP Scope Identified — {len(ips_in_list)} Hosts in Assessment",
                    host=ips_in_list[0], port="—", service="network",
                    description=f"Assessment scope includes {len(ips_in_list)} IP addresses: {', '.join(ips_in_list[:8])}{'...' if len(ips_in_list)>8 else ''}. Each host represents a potential entry point requiring full security validation including port scanning, service enumeration, and vulnerability assessment.",
                    evidence="\n".join(ips_in_list[:20]),
                    source_file=fpath,
                    recommendation="1. Ensure all listed hosts have been fully scanned. 2. Validate that no hosts are missing from scope. 3. Decommission any hosts not actively required. 4. Maintain an asset register with owner and purpose for each host."
                ))

        # 43. Discovery scan — aborted = incomplete reconnaissance
        if in_path("discovery_scan"):
            if "aborting" in content_lower or "aborted" in content_lower:
                self.findings.append(Finding(
                    severity="medium",
                    title="Network Discovery Scan Aborted — Host Discovery Incomplete",
                    host=host or "Network", port="—", service="network",
                    description="The automated network discovery scan was aborted before completion. This means live hosts in scope may not have been fully identified, leaving potential vulnerabilities unassessed.",
                    evidence=content.strip(),
                    source_file=fpath,
                    recommendation="1. Re-run network discovery scan to completion. 2. Use multiple discovery methods (ICMP, TCP SYN, ARP). 3. Cross-reference results with asset inventory to ensure no hosts are missed."
                ))
            else:
                discovered = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', content)
                if discovered:
                    self.findings.append(Finding(
                        severity="low",
                        title=f"Network Discovery Completed — {len(set(discovered))} Live Hosts Found",
                        host=discovered[0], port="—", service="network",
                        description=f"Network discovery identified {len(set(discovered))} live hosts in scope. Each live host requires further enumeration and vulnerability assessment.",
                        evidence="\n".join(list(dict.fromkeys(discovered))[:15]),
                        source_file=fpath,
                        recommendation="1. Ensure all discovered hosts are included in full vulnerability assessment. 2. Investigate any unexpected or unknown hosts. 3. Maintain network topology documentation."
                    ))

        # 44. Port scan log — orchestration log showing completed scans
        if in_path("port_scan") and "port_scan.log" in fpath.lower():
            completed = re.findall(r'(\w[\w\s]+) (?:scan|enumeration) completed', content, re.IGNORECASE)
            workspace = re.search(r'workspace[:\s]+(\S+)', content, re.IGNORECASE)
            ws = workspace.group(1) if workspace else "target"
            if completed or "starting" in content_lower:
                self.findings.append(Finding(
                    severity="medium",
                    title=f"Comprehensive Port Scan Campaign Conducted Against {ws}",
                    host=host or "Multiple Hosts", port="—", service="network",
                    description=f"A comprehensive port scanning campaign was conducted including: {', '.join(completed[:5]) if completed else 'TCP full scan, UDP scan, service enumeration'}. Full port scanning maps all network services and identifies attack surface.",
                    evidence=content[:600],
                    source_file=fpath,
                    recommendation="1. Review all open ports identified in scan results. 2. Close or firewall all unnecessary ports. 3. Ensure all open service versions are patched. 4. Implement network intrusion detection to alert on port scanning activity."
                ))

        # Extended patterns — covers remaining file types
        self._extended_patterns(content, content_lower, fpath, host)

    # ------------------------------------------------------------------ #
    #  Helpers
    # ------------------------------------------------------------------ #
    def _extract_host(self, content: str) -> str:
        match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', content)
        return match.group(1) if match else "Unknown"

    def _extract_snippet(self, content: str, keyword: str, length: int = 400) -> str:
        idx = content.lower().find(keyword.lower())
        if idx == -1:
            return content[:length]
        start = max(0, idx - 100)
        return content[start:start + length]

    def _classify_severity(self, text: str) -> str:
        for sev in ["critical", "high", "medium", "low"]:
            for kw in SEVERITY_KEYWORDS[sev]:
                if kw in text:
                    return sev
        return "medium"

    def _deduplicate(self, findings: List[Finding]) -> List[Finding]:
        seen = set()
        unique = []
        for f in findings:
            key = (f.title, f.host, f.port)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        # Sort by severity
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        unique.sort(key=lambda x: order.get(x.severity, 4))
        return unique


    def _extended_patterns(self, content: str, content_lower: str,
                           fpath: str, host: str) -> None:
        """Extra detection patterns for all remaining file types."""
        import os, re as _re
        fname = os.path.basename(fpath).lower()
        fdir  = fpath.lower()

        def ip(block): 
            m = _re.match(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', block.strip())
            return m.group(1) if m else host

        def snip(needle, w=400):
            idx = content_lower.find(needle.lower())
            if idx == -1: return content[:w]
            return content[max(0,idx-50):idx+w]

        def add(sev, title, h, port, svc, desc, evidence, rec):
            self.findings.append(Finding(
                severity=sev, title=title, host=h, port=str(port),
                service=svc, description=desc, evidence=evidence[:800],
                source_file=fpath, recommendation=rec
            ))

        # ── testssl.sh output ──────────────────────────────────────────────
        if "testssl" in content_lower or ("tls 1" in content_lower and "offered" in content_lower and "deprecated" in content_lower):
            tgt = _re.search(r'-->> (\d+\.\d+\.\d+\.\d+):(\d+)', content)
            h = tgt.group(1) if tgt else host
            p = tgt.group(2) if tgt else "443"

            if "sslv3" in content_lower and "not ok" in content_lower:
                add("critical", f"SSLv3 Offered on {h}:{p} — POODLE Attack Risk", h, p, "https",
                    f"testssl.sh confirms SSLv3 is offered on {h}:{p}. SSLv3 is vulnerable to the POODLE attack (CVE-2014-3566) which allows decryption of encrypted traffic. SSLv3 was deprecated in 2015.",
                    snip("sslv3"), "1. Disable SSLv3 immediately in server TLS config. 2. Set minimum protocol to TLS 1.2. 3. Verify with testssl.sh after remediation.")

            if _re.search(r'tls 1\s+offered\s*\(deprecated\)', content_lower):
                add("high", f"TLS 1.0 Offered on {h}:{p} — Deprecated Protocol", h, p, "https",
                    f"TLS 1.0 is offered on {h}:{p}. TLS 1.0 is deprecated (RFC 8996) and vulnerable to BEAST and POODLE attacks. PCI DSS 3.2+ requires disabling TLS 1.0.",
                    snip("tls 1"), "1. Disable TLS 1.0 in server configuration. 2. Enforce minimum TLS 1.2. 3. Enable TLS 1.3 if supported.")

            if _re.search(r'tls 1\.1\s+offered\s*\(deprecated\)', content_lower):
                add("high", f"TLS 1.1 Offered on {h}:{p} — Deprecated Protocol", h, p, "https",
                    f"TLS 1.1 is offered on {h}:{p}. TLS 1.1 is deprecated (RFC 8996) and considered insecure. Clients connecting with TLS 1.1 are at risk of protocol downgrade attacks.",
                    snip("tls 1.1"), "1. Disable TLS 1.1 in server configuration. 2. Enforce TLS 1.2 minimum. 3. Test with testssl.sh after changes.")

            if _re.search(r'tls 1\.3\s+not offered and downgraded', content_lower):
                add("medium", f"TLS 1.3 Not Available on {h}:{p} — Modern Protocol Missing", h, p, "https",
                    f"TLS 1.3 is not offered on {h}:{p}. TLS 1.3 provides significant security improvements including forward secrecy by default and removal of legacy cryptographic algorithms. Connections fall back to older TLS versions.",
                    snip("tls 1.3"), "1. Upgrade server TLS library to support TLS 1.3. 2. Enable TLS 1.3 cipher suites. 3. This often requires upgrading OpenSSL to 1.1.1+.")

            if "low: 64 bit" in content_lower and "not ok" in content_lower:
                add("critical", f"Weak 64-bit / DES / RC4 Ciphers Offered on {h}:{p}", h, p, "https",
                    f"testssl.sh found weak 64-bit or DES/RC4 cipher suites offered on {h}:{p}. These ciphers can be broken via SWEET32 (CVE-2016-2183) or statistical attacks, allowing session decryption.",
                    snip("low: 64 bit"), "1. Disable all DES, RC4, and 3DES cipher suites. 2. Only allow AEAD ciphers (AES-GCM, ChaCha20). 3. Set cipher string to HIGH:!aNULL:!MD5:!3DES.")

            if "3des" in content_lower and ("offered" in content_lower or "not ok" in content_lower):
                add("high", f"3DES (Triple-DES) Cipher Offered on {h}:{p} — SWEET32 Risk", h, p, "https",
                    f"Triple-DES ciphers are offered on {h}:{p}. 3DES is vulnerable to the SWEET32 birthday attack (CVE-2016-2183) which can recover plaintext from long-lived sessions.",
                    snip("3des"), "1. Disable all 3DES cipher suites. 2. Use AES-GCM alternatives. 3. Update SSL/TLS configuration.")

            if "forward secrecy" in content_lower and "offered" in content_lower:
                add("low", f"Forward Secrecy Status Confirmed on {h}:{p}", h, p, "https",
                    f"testssl.sh assessed forward secrecy configuration on {h}:{p}. Forward secrecy ensures past sessions cannot be decrypted if the server's private key is later compromised. Verify strong FS ciphers are prioritised.",
                    snip("forward secrecy"), "1. Ensure ECDHE/DHE key exchange is preferred. 2. Disable RSA key exchange (no forward secrecy). 3. Use DHE params of at least 2048-bit.")

        # ── Nikto scan ────────────────────────────────────────────────────
        if "nikto" in content_lower or ("target ip:" in content_lower and "target port:" in content_lower):
            # ASP.NET version disclosure
            if "x-aspnet-version" in content_lower:
                ver = _re.search(r'x-aspnet-version.*?(\d[\d\.]+)', content_lower)
                v = ver.group(1) if ver else "unknown"
                h2 = _re.search(r'target ip:\s+(\d+\.\d+\.\d+\.\d+)', content_lower)
                h2 = h2.group(1) if h2 else host
                add("medium", f"ASP.NET Version Disclosed on {h2}: {v}",
                    h2, "80/443", "http",
                    f"The X-ASP.NET-Version response header discloses the exact .NET framework version ({v}) on {h2}. Version disclosure helps attackers identify known vulnerabilities specific to that version.",
                    snip("x-aspnet-version"),
                    "1. Remove X-ASP.NET-Version header in web.config: <httpRuntime enableVersionHeader='false'/>. 2. Also suppress X-Powered-By header.")

            if "server: microsoft-iis" in content_lower:
                iis_ver = _re.search(r'server: microsoft-iis/([\d\.]+)', content_lower)
                v = iis_ver.group(1) if iis_ver else "unknown"
                h2 = _re.search(r'target ip:\s+(\d+\.\d+\.\d+\.\d+)', content_lower)
                h2 = h2.group(1) if h2 else host
                add("medium", f"IIS Version Disclosed on {h2}: Microsoft-IIS/{v}",
                    h2, "80/443", "http",
                    f"The Server response header discloses Microsoft IIS version {v} on {h2}. This allows targeted exploitation using known IIS-specific CVEs.",
                    snip("server: microsoft-iis"),
                    "1. Remove Server header via URL Rewrite or custom IIS config. 2. Keep IIS patched to latest version. 3. Suppress all version banners.")

            if "x-powered-by: asp.net" in content_lower:
                h2 = _re.search(r'target ip:\s+(\d+\.\d+\.\d+\.\d+)', content_lower)
                h2 = h2.group(1) if h2 else host
                add("low", f"X-Powered-By: ASP.NET Header Disclosed on {h2}",
                    h2, "80/443", "http",
                    f"The X-Powered-By header on {h2} reveals the server is running ASP.NET. Technology disclosure reduces the effort needed to find applicable exploits.",
                    snip("x-powered-by"),
                    "1. Remove X-Powered-By header in web.config. 2. Consider removing all technology-identifying headers.")

            if "trace" in content_lower and ("allowed" in content_lower or "options" in content_lower):
                h2 = _re.search(r'target ip:\s+(\d+\.\d+\.\d+\.\d+)', content_lower)
                h2 = h2.group(1) if h2 else host
                add("medium", f"HTTP TRACE Method Enabled on {h2} — XST Attack Risk",
                    h2, "80/443", "http",
                    f"HTTP TRACE method is enabled on {h2}. TRACE can be exploited for Cross-Site Tracing (XST) attacks which, combined with XSS, can steal credentials and session cookies from browser requests.",
                    snip("trace"),
                    "1. Disable TRACE method in web server config. 2. For IIS: use URL Rewrite to block TRACE. 3. For Apache: add 'TraceEnable off' to config.")

            if "anti-clickjacking" in content_lower or ("x-frame-options" in content_lower and "not present" in content_lower):
                h2 = _re.search(r'target ip:\s+(\d+\.\d+\.\d+\.\d+)', content_lower)
                h2 = h2.group(1) if h2 else host
                add("medium", f"Clickjacking Protection Missing on {h2} — X-Frame-Options Absent",
                    h2, "80/443", "http",
                    f"Nikto scan on {h2} confirms X-Frame-Options header is absent. This allows the page to be embedded in a malicious iframe for clickjacking attacks, potentially stealing credentials or triggering unauthorised actions.",
                    snip("clickjacking"),
                    "1. Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header. 2. Implement Content-Security-Policy with frame-ancestors directive.")

            if "x-content-type-options" in content_lower and ("not set" in content_lower or "not present" in content_lower):
                h2 = _re.search(r'target ip:\s+(\d+\.\d+\.\d+\.\d+)', content_lower)
                h2 = h2.group(1) if h2 else host
                add("low", f"X-Content-Type-Options Header Missing on {h2}",
                    h2, "80/443", "http",
                    f"Nikto confirms X-Content-Type-Options header is not set on {h2}. Without this header, browsers may MIME-sniff responses, potentially executing uploaded files as scripts.",
                    snip("x-content-type"), "1. Add 'X-Content-Type-Options: nosniff' to all HTTP responses.")

        # ── WAF tests ─────────────────────────────────────────────────────
        if "wafw00f" in content_lower or "waf" in fname:
            # WAF detected
            waf_detected = _re.search(r'is behind (.+?) WAF', content, _re.IGNORECASE)
            if waf_detected:
                waf_name = waf_detected.group(1)
                waf_host = _re.search(r'checking https?://(\d+\.\d+\.\d+\.\d+)', content_lower)
                h2 = waf_host.group(1) if waf_host else host
                add("low", f"WAF Detected on {h2}: {waf_name}",
                    h2, "80/443", "http",
                    f"wafw00f identified a {waf_name} Web Application Firewall protecting {h2}. WAF presence confirms the target is aware of web threats. However, WAFs can be bypassed and should not be relied upon as sole protection.",
                    snip(waf_name),
                    "1. Keep WAF rules updated. 2. Do not rely solely on WAF — fix underlying vulnerabilities. 3. Review WAF bypass techniques for your product.")
            # WAF not detected / error
            elif "not behind a waf" in content_lower or "appears to be down" in content_lower or "ssl error" in content_lower:
                waf_host = _re.search(r'testing (\d+\.\d+\.\d+\.\d+)', content_lower)
                h2 = waf_host.group(1) if waf_host else host
                port_m = _re.search(r'testing \d+\.\d+\.\d+\.\d+:(\d+)', content_lower)
                p = port_m.group(1) if port_m else "443"
                if "ssl error" in content_lower or "record layer failure" in content_lower:
                    add("high", f"SSL/TLS Handshake Failure on {h2}:{p} — Service Misconfiguration",
                        h2, p, "https",
                        f"WAF detection against {h2}:{p} failed due to SSL record layer failure. This indicates a TLS misconfiguration that causes connection failures — potentially affecting all clients attempting to connect securely.",
                        snip("ssl error"),
                        "1. Investigate TLS certificate and cipher configuration on {h2}:{p}. 2. Test with: openssl s_client -connect {h2}:{p}. 3. Check for certificate chain issues or protocol mismatches.")
                else:
                    add("high", f"No WAF Detected on {h2}:{p} — Web Application Unprotected",
                        h2, p, "http",
                        f"wafw00f found no WAF protecting {h2}:{p}. Web applications without WAF protection are directly exposed to exploitation of injection, XSS, and other OWASP Top 10 vulnerabilities.",
                        snip("not behind"),
                        "1. Deploy a WAF (Azure WAF, AWS WAF, Cloudflare, ModSecurity). 2. Prioritise fixing underlying vulnerabilities. 3. Implement input validation in application code.")

            # Multiple targets tested
            hosts_tested = list(dict.fromkeys(_re.findall(r'testing (\d+\.\d+\.\d+\.\d+:\d+)', content_lower)))
            if len(hosts_tested) > 1:
                add("medium", f"WAF Assessment Conducted Against {len(hosts_tested)} Endpoints",
                    host or hosts_tested[0].split(":")[0], "80/443", "http",
                    f"WAF fingerprinting was performed against {len(hosts_tested)} web endpoints: {', '.join(hosts_tested[:5])}. WAF bypass testing is part of a comprehensive web application assessment.",
                    "\n".join(hosts_tested[:10]),
                    "1. Ensure all web-facing endpoints are protected by a WAF. 2. Review WAF coverage for all discovered endpoints. 3. Keep WAF rules updated.")

        # ── technologies.txt / WhatWeb ─────────────────────────────────────
        if "technologies" in fname or ("whatweb" in content_lower) or ("httpserver[microsoft-iis" in content_lower):
            # Old Windows Server versions
            old_win = _re.findall(r'(\d+\.\d+\.\d+\.\d+).*?Windows.*?200[0-9]', content, _re.IGNORECASE)
            for ow in old_win[:5]:
                h2 = _re.search(r'(\d+\.\d+\.\d+\.\d+)', ow)
                h2 = h2.group(1) if h2 else host
                add("critical", f"End-of-Life Windows Server OS Detected on {h2}",
                    h2, "80/443", "http",
                    f"Technology fingerprinting identified an end-of-life Windows Server OS on {h2}. EOL operating systems no longer receive security patches, leaving them vulnerable to all publicly disclosed CVEs with no vendor remediation.",
                    snip(h2[:12]),
                    "1. Upgrade to a supported Windows Server version immediately. 2. If upgrade is not immediate, isolate host from internet access. 3. Apply all available patches and harden the system.")

            # IIS version disclosure
            iis_hosts = _re.findall(r'(\d+\.\d+\.\d+\.\d+).*?microsoft-iis\[([\d\.]+)\]', content_lower)
            for ih, iv in iis_hosts[:5]:
                add("medium", f"IIS {iv} Version Disclosed via HTTP Response on {ih}",
                    ih, "80/443", "http",
                    f"WhatWeb fingerprinted Microsoft IIS version {iv} on {ih}. Server version disclosure helps attackers pinpoint known IIS CVEs. IIS 10.0 (Server 2016/2019) is current; earlier versions are EOL.",
                    snip(ih),
                    "1. Remove Server header from IIS responses. 2. Ensure IIS is on a supported version. 3. Apply all IIS cumulative patches.")

            # ASP.NET detected
            if "x-powered-by[asp.net]" in content_lower or "asp_net" in content_lower:
                asp_hosts = _re.findall(r'(\d+\.\d+\.\d+\.\d+)', content)
                h2 = asp_hosts[0] if asp_hosts else host
                add("low", f"ASP.NET Technology Stack Exposed on {h2}",
                    h2, "80/443", "http",
                    f"ASP.NET framework is disclosed via HTTP headers on {h2}. Technology stack exposure aids targeted attacks using ASP.NET-specific vulnerabilities (ViewState deserialization, path traversal, etc.).",
                    snip("asp.net"),
                    "1. Remove X-Powered-By and X-AspNet-Version headers. 2. Ensure ASP.NET is updated to latest version. 3. Review ViewState MAC validation settings.")

            # Password field found
            if "passwordfield" in content_lower:
                pw_hosts = _re.findall(r'(\d+\.\d+\.\d+\.\d+)', content)
                h2 = pw_hosts[0] if pw_hosts else host
                add("medium", f"Login Form with Password Field Detected on {h2}",
                    h2, "80/443", "http",
                    f"A web login form with a password field was discovered on {h2}. Login forms are high-value targets for credential brute-forcing, credential stuffing, and SQL injection attacks.",
                    snip("passwordfield"),
                    "1. Implement account lockout after failed attempts. 2. Enforce multi-factor authentication. 3. Verify login form is only accessible over HTTPS. 4. Test for SQL injection in login parameters.")

            # Azure Application Gateway disclosed
            if "azure-application-gateway" in content_lower:
                agw_hosts = _re.findall(r'(\d+\.\d+\.\d+\.\d+).*?azure-application-gateway', content_lower)
                h2 = agw_hosts[0] if agw_hosts else host
                add("low", f"Azure Application Gateway Infrastructure Disclosed on {h2}",
                    h2, "80/443", "http",
                    f"HTTP responses from {h2} disclose the use of Azure Application Gateway. Infrastructure disclosure narrows the attack surface and may indicate Azure-specific misconfigurations to probe.",
                    snip("azure-application-gateway"),
                    "1. Configure custom Server header to remove infrastructure disclosure. 2. Review Azure Application Gateway WAF rules. 3. Enable Azure Security Centre recommendations.")

        # ── MSF current_workspace / msf_notes ────────────────────────────
        if "current_workspace" in fname or ("workspace:" in content_lower and ("hosts" in content_lower or "services" in content_lower)):
            # EOL Windows detected in workspace
            eol_win = _re.findall(r'(\d+\.\d+\.\d+\.\d+)\s+\S*\s+\S*\s+(windows (?:2008|2003|2000|xp|vista|7|8))', content_lower)
            for ew_ip, ew_ver in eol_win[:8]:
                add("critical", f"End-of-Life OS on {ew_ip}: {ew_ver.title()}",
                    ew_ip, "—", "os",
                    f"Metasploit workspace identifies {ew_ip} running {ew_ver.title()}, which is end-of-life and no longer receives Microsoft security patches. EOL systems are primary targets for ransomware and APT groups.",
                    snip(ew_ip),
                    "1. Immediately plan migration to supported OS. 2. Isolate EOL host behind strict firewall rules. 3. Apply all available patches as temporary measure. 4. Prioritise for decommission or upgrade.")

            # ICS/network device OS (Cisco IOS, embedded)
            ics_hosts = _re.findall(r'(\d+\.\d+\.\d+\.\d+)\s+\S*\s+\S*\s+(ios|embedded|firmware)', content_lower)
            for ic_ip, ic_os in ics_hosts[:5]:
                add("high", f"Network/Embedded Device Identified: {ic_ip} ({ic_os.upper()})",
                    ic_ip, "—", "network-device",
                    f"Metasploit identifies {ic_ip} as running {ic_os.upper()} (network device or embedded OS). Network devices are high-value targets — compromise allows traffic interception and network-wide lateral movement.",
                    snip(ic_ip),
                    "1. Ensure device firmware is on latest version. 2. Disable telnet, use SSH only. 3. Restrict management interface access by IP. 4. Enable logging and monitoring on device.")

            # Identify hosts with SNMP in workspace
            snmp_hosts = _re.findall(r'(\d+\.\d+\.\d+\.\d+)\s+161\s+udp\s+snmp', content_lower)
            for sh in snmp_hosts[:5]:
                add("high", f"SNMP Service Exposed on {sh}:161",
                    sh, "161", "snmp",
                    f"Metasploit workspace records SNMP (UDP/161) on {sh}. SNMP v1/v2c use community strings transmitted in cleartext. Default community string 'public' allows reading full device configuration.",
                    snip(sh),
                    "1. Disable SNMPv1/v2c, use SNMPv3 with authentication. 2. Change default community string immediately. 3. Restrict SNMP access by ACL to management hosts only.")

        # ── MSF notes CSV ────────────────────────────────────────────────
        if "notes" in fname and (".csv" in fname or "msf" in content_lower or "nmap_fingerprint" in content_lower):
            # Fortinet device with default cert
            if "fortinet" in content_lower or "fortigate" in content_lower:
                forti_hosts = _re.findall(r'"(\d+\.\d+\.\d+\.\d+)".*?fortinet', content_lower)
                h2 = forti_hosts[0] if forti_hosts else host
                add("high", f"Fortinet Device Default Self-Signed Certificate on {h2}",
                    h2, "443", "https",
                    f"The Fortinet device on {h2} is presenting a default self-signed certificate (CN=FG*). Default certificates indicate the device has not been fully hardened and default credentials may still be active.",
                    snip("fortinet"),
                    "1. Replace default certificate with a CA-signed certificate. 2. Change all default Fortinet passwords immediately. 3. Review Fortinet hardening guide. 4. Check for known FortiOS CVEs.")

            # TRACE method in notes
            if "risky methods" in content_lower and "trace" in content_lower:
                trace_hosts = _re.findall(r'"(\d+\.\d+\.\d+\.\d+)".*?risky methods.*?trace', content_lower)
                h2 = trace_hosts[0] if trace_hosts else host
                add("medium", f"HTTP TRACE Method Enabled on {h2} — XST Vulnerability",
                    h2, "443", "https",
                    f"Nmap NSE scripts recorded via Metasploit confirm HTTP TRACE method is enabled on {h2}. TRACE enables Cross-Site Tracing (XST) attacks.",
                    snip("trace"),
                    "1. Disable HTTP TRACE in web server configuration. 2. For Nginx: limit_except GET POST { deny all; }. 3. For Apache: TraceEnable off.")

            # Old OS in notes
            for os_ver in ["2008", "2003", "2000"]:
                if f"windows.*{os_ver}" in content_lower or f'os_version.*{os_ver}' in content_lower:
                    eol_h = _re.search(r'"(\d+\.\d+\.\d+\.\d+)"', content)
                    h2 = eol_h.group(1) if eol_h else host
                    add("critical", f"End-of-Life Windows Server {os_ver} Detected via OS Fingerprint",
                        h2, "—", "os",
                        f"Nmap OS fingerprinting (Metasploit notes) identifies Windows Server {os_ver} on {h2}. This OS reached end-of-life and no longer receives security updates from Microsoft.",
                        snip(os_ver),
                        "1. Plan immediate migration to Windows Server 2019/2022. 2. Apply Extended Security Updates if still available. 3. Isolate from internet-facing network segments.")
                    break

            # SSL-date randomness anomaly
            if "tls randomness does not represent time" in content_lower:
                tls_hosts = _re.findall(r'"(\d+\.\d+\.\d+\.\d+)".*?tls randomness', content_lower)
                for th in (tls_hosts or [host])[:3]:
                    add("low", f"TLS Random Field Anomaly on {th} — Potential Fingerprinting Risk",
                        th, "443", "https",
                        f"The TLS ServerHello random field on {th} does not represent time, which is unusual and may indicate the use of a non-standard TLS implementation, virtual environment, or specific vendor stack.",
                        snip("tls randomness"),
                        "1. Investigate TLS implementation on this host. 2. Ensure TLS library is up to date. 3. Check for known CVEs in the identified TLS stack.")

            # Azure Bastion certificate leak
            if "bastion.azure.com" in content_lower:
                bas_hosts = _re.findall(r'"(\d+\.\d+\.\d+\.\d+)"', content)
                h2 = bas_hosts[0] if bas_hosts else host
                add("medium", f"Azure Bastion Service Certificate Exposed on {h2}",
                    h2, "443", "https",
                    f"The TLS certificate on {h2} references an Azure Bastion service (bastion.azure.com). Azure Bastion exposure reveals cloud infrastructure details and should be verified for proper access controls.",
                    snip("bastion"),
                    "1. Verify Azure Bastion is not publicly accessible (should be private). 2. Review NSG rules restricting Bastion port 443. 3. Enable Azure Bastion diagnostic logging.")

        # ── CSV hosts/services files ───────────────────────────────────────
        if fname.endswith(".csv") and ("hosts" in fname or "services" in fname or "notes" in fname):
            # EOL OS in hosts CSV
            for os_ver, os_name in [("2008","Windows Server 2008"),("2003","Windows Server 2003"),("2000","Windows Server 2000")]:
                eol_rows = [r for r in content.split("\n") if os_ver in r and _re.search(r'\d+\.\d+\.\d+\.\d+', r)]
                for row in eol_rows[:5]:
                    eol_ip = _re.search(r'"?(\d+\.\d+\.\d+\.\d+)"?', row)
                    if eol_ip:
                        add("critical", f"End-of-Life {os_name} Detected: {eol_ip.group(1)}",
                            eol_ip.group(1), "—", "os",
                            f"{os_name} detected on {eol_ip.group(1)} via asset inventory. {os_name} is end-of-life with no security patches since their respective EOL dates. These hosts are prime ransomware and APT targets.",
                            row.strip(),
                            f"1. Migrate {eol_ip.group(1)} to Windows Server 2019/2022 immediately. 2. Implement network isolation until migration. 3. Apply all available patches.")

            # Open database ports in services CSV
            db_ports = {"1433":"MSSQL","3306":"MySQL","5432":"PostgreSQL","1521":"Oracle","50000":"DB2","27017":"MongoDB","6379":"Redis","5984":"CouchDB"}
            for dp, dname in db_ports.items():
                db_rows = [r for r in content.split("\n") if f'"{dp}"' in r and "open" in r.lower()]
                for row in db_rows[:3]:
                    db_ip = _re.search(r'"?(\d+\.\d+\.\d+\.\d+)"?', row)
                    if db_ip:
                        add("critical", f"Database Service {dname} Exposed on {db_ip.group(1)}:{dp}",
                            db_ip.group(1), dp, dname.lower(),
                            f"{dname} (port {dp}) is open on {db_ip.group(1)}. Database services exposed without authentication or accessible from untrusted networks risk complete data theft, ransomware, and data destruction.",
                            row.strip(),
                            f"1. Firewall {dname} port {dp} to only trusted application servers. 2. Require strong authentication. 3. Encrypt data at rest and in transit. 4. Audit database access logs.")

            # RDP open
            rdp_rows = [r for r in content.split("\n") if '"3389"' in r and "open" in r.lower()]
            for row in rdp_rows[:5]:
                rdp_ip = _re.search(r'"?(\d+\.\d+\.\d+\.\d+)"?', row)
                if rdp_ip:
                    add("high", f"RDP (Port 3389) Exposed on {rdp_ip.group(1)}",
                        rdp_ip.group(1), "3389", "rdp",
                        f"Remote Desktop Protocol is open on {rdp_ip.group(1)}. Internet-exposed RDP is the leading vector for ransomware intrusion. BlueKeep (CVE-2019-0708) and DejaBlue target unpatched RDP.",
                        row.strip(),
                        "1. Block port 3389 from internet access. 2. Require VPN for RDP access. 3. Enable Network Level Authentication. 4. Apply MS patches for BlueKeep/DejaBlue.")

            # Telnet open
            tel_rows = [r for r in content.split("\n") if '"23"' in r and "open" in r.lower()]
            for row in tel_rows[:5]:
                tel_ip = _re.search(r'"?(\d+\.\d+\.\d+\.\d+)"?', row)
                if tel_ip:
                    add("critical", f"Telnet Service Open on {tel_ip.group(1)}:23 — Cleartext Protocol",
                        tel_ip.group(1), "23", "telnet",
                        f"Telnet (port 23) is open on {tel_ip.group(1)}. Telnet transmits all data including credentials in cleartext and should not be used in any environment. It is exploitable via simple network sniffing.",
                        row.strip(),
                        "1. Disable Telnet immediately. 2. Replace with SSH. 3. Block port 23 at firewall perimeter.")

            # VNC open
            vnc_rows = [r for r in content.split("\n") if '"5900"' in r and "open" in r.lower()]
            for row in vnc_rows[:3]:
                vnc_ip = _re.search(r'"?(\d+\.\d+\.\d+\.\d+)"?', row)
                if vnc_ip:
                    add("high", f"VNC Service Open on {vnc_ip.group(1)}:5900",
                        vnc_ip.group(1), "5900", "vnc",
                        f"VNC is open on {vnc_ip.group(1)}. VNC provides full graphical desktop access and is frequently targeted by attackers via brute force, default credentials, and unpatched vulnerabilities.",
                        row.strip(),
                        "1. Restrict VNC access by firewall to trusted IPs only. 2. Require VPN for VNC access. 3. Set a strong VNC password. 4. Use TLS-encrypted VNC where possible.")

            # LDAP open
            ldap_rows = [r for r in content.split("\n") if ('"389"' in r or '"636"' in r) and "open" in r.lower()]
            for row in ldap_rows[:3]:
                ldap_ip = _re.search(r'"?(\d+\.\d+\.\d+\.\d+)"?', row)
                p2 = "636" if '"636"' in row else "389"
                if ldap_ip:
                    add("high", f"LDAP{'S' if p2=='636' else ''} Service Exposed on {ldap_ip.group(1)}:{p2}",
                        ldap_ip.group(1), p2, "ldap",
                        f"LDAP{'S' if p2=='636' else ''} port {p2} is open on {ldap_ip.group(1)}. Exposed LDAP can allow anonymous enumeration of Active Directory users, groups, and organisational data without authentication.",
                        row.strip(),
                        "1. Restrict LDAP access to authorised servers only. 2. Disable anonymous LDAP bind. 3. Enforce LDAP signing and channel binding. 4. Use LDAPS (636) instead of plain LDAP.")

            # PPTP VPN
            pptp_rows = [r for r in content.split("\n") if '"1723"' in r and ("open" in r.lower() or "filtered" in r.lower())]
            for row in pptp_rows[:3]:
                pptp_ip = _re.search(r'"?(\d+\.\d+\.\d+\.\d+)"?', row)
                if pptp_ip:
                    add("high", f"PPTP VPN Exposed on {pptp_ip.group(1)}:1723 — Deprecated Insecure Protocol",
                        pptp_ip.group(1), "1723", "vpn",
                        f"PPTP VPN (port 1723) is exposed on {pptp_ip.group(1)}. PPTP uses MS-CHAPv2 which is completely broken — Microsoft tools can crack it in under 24 hours. PPTP provides essentially no security.",
                        row.strip(),
                        "1. Disable PPTP VPN. 2. Replace with IKEv2/IPSec or WireGuard. 3. Block port 1723 at firewall.")

            # Java RMI registry
            rmi_rows = [r for r in content.split("\n") if '"1099"' in r and ("open" in r.lower() or "filtered" in r.lower())]
            for row in rmi_rows[:3]:
                rmi_ip = _re.search(r'"?(\d+\.\d+\.\d+\.\d+)"?', row)
                if rmi_ip:
                    add("critical", f"Java RMI Registry Exposed on {rmi_ip.group(1)}:1099",
                        rmi_ip.group(1), "1099", "rmi",
                        f"Java RMI Registry (port 1099) is exposed on {rmi_ip.group(1)}. Java RMI is exploitable for remote code execution via deserialization attacks (ysoserial). This is a critical vector for full system compromise.",
                        row.strip(),
                        "1. Firewall port 1099 immediately to block all external access. 2. Migrate away from Java RMI to REST/gRPC. 3. Apply Java deserialization patches. 4. Implement SecurityManager for RMI.")

            # TFTP open
            tftp_rows = [r for r in content.split("\n") if '"69"' in r and ("open" in r.lower() or "unknown" in r.lower())]
            for row in tftp_rows[:3]:
                tftp_ip = _re.search(r'"?(\d+\.\d+\.\d+\.\d+)"?', row)
                if tftp_ip:
                    add("high", f"TFTP Service Detected on {tftp_ip.group(1)}:69",
                        tftp_ip.group(1), "69", "tftp",
                        f"TFTP (UDP 69) is accessible on {tftp_ip.group(1)}. TFTP has no authentication and transmits data in cleartext. It is commonly used to exfiltrate network device configurations including passwords.",
                        row.strip(),
                        "1. Disable TFTP unless required for network device config management. 2. Restrict TFTP by source IP. 3. Replace with SFTP for file transfers.")

            # Multiple open services on same host = attack surface
            open_services = [r for r in content.split("\n") if "open" in r.lower() and _re.search(r'\d+\.\d+\.\d+\.\d+', r)]
            if len(open_services) > 10:
                first_ip = _re.search(r'"?(\d+\.\d+\.\d+\.\d+)"?', open_services[0])
                h2 = first_ip.group(1) if first_ip else host
                add("medium", f"Large Service Attack Surface Detected — {len(open_services)} Open Services",
                    h2, "—", "network",
                    f"Asset inventory records {len(open_services)} open service entries across the scope. A broad service attack surface increases exposure. Each open service is a potential entry point for exploitation.",
                    "\n".join(open_services[:10]),
                    "1. Audit all open services against business requirements. 2. Close all unnecessary services. 3. Implement network segmentation. 4. Conduct service-specific vulnerability assessment.")

        # ── common_ports_scan / tcp_full_scan ──────────────────────────────
        if "common_ports" in fname or "tcp_full" in fname or "tcp_scan" in fname:
            # OS disclosure via Nmap
            os_guesses = _re.findall(r'Aggressive OS guesses?:\s*(.+?)(?:\n|$)', content)
            for guess in os_guesses[:3]:
                og_host = _re.search(r'Nmap scan report for (\d+\.\d+\.\d+\.\d+)', content)
                h2 = og_host.group(1) if og_host else host
                add("low", f"OS Fingerprint Disclosed via Nmap on {h2}: {guess[:60]}",
                    h2, "—", "os",
                    f"Nmap successfully fingerprinted the OS on {h2}: {guess[:100]}. OS disclosure assists in identifying version-specific CVEs and custom exploitation.",
                    guess[:300],
                    "1. Enable network-level firewall to suppress OS fingerprinting probes. 2. Randomise or suppress TCP/IP stack characteristics where possible. 3. Network IDS rule: alert on Nmap OS detection probes.")

            # Dangerously open legacy ports
            for port, svc, risk in [
                ("23", "Telnet", "cleartext credentials"),
                ("69", "TFTP", "unauthenticated file access"),
                ("111", "RPC Portmapper", "remote procedure call exploitation"),
                ("512", "rexec", "cleartext remote execution"),
                ("513", "rlogin", "cleartext trust-based login"),
                ("514", "rsh", "cleartext trusted shell"),
            ]:
                if f"{port}/tcp" in content and "open" in content.lower():
                    affected = _re.findall(fr'(\d+\.\d+\.\d+\.\d+)(?:.*\n)*?.*{port}/tcp\s+open', content)
                    for ah in (affected or [host])[:3]:
                        add("critical", f"Legacy Insecure Service {svc} Open on {ah}:{port}",
                            ah, port, svc.lower(),
                            f"{svc} (port {port}) is open on {ah}. This is an inherently insecure legacy service ({risk}). No modern security justification exists for running this service.",
                            snip(f"{port}/tcp"),
                            f"1. Immediately disable {svc} on port {port}. 2. Replace with SSH/SFTP/equivalent. 3. Block port {port} at all firewall layers.")

            # Unrecognized service fingerprint = unusual
            if "unrecognized despite returning data" in content_lower or "1 service unrecognized" in content_lower:
                unr_host = _re.search(r'Nmap scan report for (\d+\.\d+\.\d+\.\d+)', content)
                h2 = unr_host.group(1) if unr_host else host
                add("medium", f"Unrecognised Service Detected on {h2} — Manual Investigation Required",
                    h2, "—", "unknown",
                    f"Nmap detected a service on {h2} that returned data but could not be fingerprinted. Unrecognised services may be custom backdoors, obfuscated malware, or misconfigured applications.",
                    snip("unrecognized"),
                    "1. Manually inspect the service with netcat or curl. 2. Capture traffic with Wireshark for analysis. 3. Compare against known legitimate services on this host. 4. Escalate to IR team if suspicious.")

            # LDAP/RMI filtered ports (attack surface)
            ldap_filtered = _re.findall(r'(\d+\.\d+\.\d+\.\d+)(?:.*\n)*?.*(?:389|636|1099|3268|3269)/tcp\s+filtered', content)
            if ldap_filtered:
                h2 = ldap_filtered[0]
                add("medium", f"LDAP/AD Ports Filtered on {h2} — Active Directory Presence Inferred",
                    h2, "389/636", "ldap",
                    f"LDAP and Global Catalog ports (389, 636, 3268, 3269) are filtered on {h2}, indicating a likely Active Directory domain controller behind a firewall. AD infrastructure is a prime target for Kerberoasting, Pass-the-Hash, and DCSync attacks.",
                    snip("389"),
                    "1. Ensure AD is not internet-accessible. 2. Implement tiered administration model. 3. Enable AD audit logging. 4. Use Microsoft Defender for Identity for AD threat detection.")

        # ── udp_scan ─────────────────────────────────────────────────────
        if "udp_scan" in fname or ("udp scan" in content_lower and "nmap" in content_lower):
            # SNMP via UDP
            snmp_udp = _re.findall(r'Nmap scan report for (\d+\.\d+\.\d+\.\d+)(?:.*\n)*?.*161/udp\s+(?:open|open\|filtered)', content)
            for su in snmp_udp[:5]:
                add("high", f"SNMP UDP/161 Exposed on {su} — Community String Risk",
                    su, "161", "snmp",
                    f"SNMP UDP port 161 is open or open|filtered on {su}. SNMPv1/v2c community strings are sent in cleartext and default community 'public' provides full device information disclosure. SNMP can be used to extract full device configuration.",
                    snip(su),
                    "1. Disable SNMPv1 and SNMPv2c. Upgrade to SNMPv3 with authentication and encryption. 2. Change community strings to complex values. 3. Restrict SNMP access by ACL.")

            # NTP open
            ntp_udp = _re.findall(r'Nmap scan report for (\d+\.\d+\.\d+\.\d+)(?:.*\n)*?.*123/udp\s+(?:open|open\|filtered)', content)
            for nu in ntp_udp[:3]:
                add("medium", f"NTP Service Exposed on {nu}:123/UDP",
                    nu, "123", "ntp",
                    f"NTP (UDP/123) is accessible on {nu}. Misconfigured NTP servers can be abused for DDoS amplification attacks (monlist command). NTP also exposes the server's clock which aids timing-based attacks.",
                    snip(nu),
                    "1. Disable NTP monlist: restrict default kod notrap nomodify nopeer noquery. 2. Apply latest NTP patches. 3. Restrict NTP queries to authorised subnets.")

            # DHCP server exposed
            dhcp_udp = _re.findall(r'Nmap scan report for (\d+\.\d+\.\d+\.\d+)(?:.*\n)*?.*67/udp\s+(?:open|filtered)', content)
            for du in dhcp_udp[:3]:
                add("medium", f"DHCP Server Port Detected on {du}:67/UDP",
                    du, "67", "dhcp",
                    f"DHCP server (UDP/67) is present on {du}. Rogue DHCP or a misconfigured DHCP server can be exploited for network-level man-in-the-middle attacks by issuing attacker-controlled gateway/DNS addresses.",
                    snip(du),
                    "1. Verify this is an authorised DHCP server. 2. Enable DHCP snooping on network switches. 3. Implement Dynamic ARP Inspection (DAI). 4. Monitor for rogue DHCP servers.")

            # X11 open
            x11_udp = _re.findall(r'Nmap scan report for (\d+\.\d+\.\d+\.\d+)(?:.*\n)*?.*6000/udp', content)
            for xu in x11_udp[:3]:
                add("high", f"X11 Service Exposed on {xu}:6000 — Remote Desktop Hijacking Risk",
                    xu, "6000", "x11",
                    f"X11 (port 6000) is open on {xu}. Exposed X11 without authentication allows attackers to capture keystrokes, screenshots, and inject input into graphical sessions — achieving full interactive GUI access.",
                    snip(xu),
                    "1. Block port 6000 at firewall. 2. Use SSH X11 forwarding (-X flag) instead of direct X11. 3. Disable X11 TCP listening: add 'nolisten tcp' to X server config.")

            # NetBIOS/WINS
            nb_udp = _re.findall(r'Nmap scan report for (\d+\.\d+\.\d+\.\d+)(?:.*\n)*?.*137/udp\s+(?:open|open\|filtered)', content)
            for nb in nb_udp[:3]:
                add("medium", f"NetBIOS Name Service on {nb}:137/UDP",
                    nb, "137", "netbios",
                    f"NetBIOS Name Service (UDP/137) is accessible on {nb}. NetBIOS facilitates NBT-NS/LLMNR poisoning attacks (Responder) which capture NTLMv2 hashes from any host making broadcast name resolution requests.",
                    snip(nb),
                    "1. Disable NetBIOS over TCP/IP where not required. 2. Disable LLMNR and NBT-NS via GPO. 3. Block UDP 137/138 and TCP 139 at network boundaries.")

        # ── FTP banner / custom tests ──────────────────────────────────────
        if "banner" in fname or ("filezilla" in content_lower and "220" in content):
            fz_ver = _re.search(r'filezilla server ([\d\.]+)', content_lower)
            fz_v = fz_ver.group(1) if fz_ver else "unknown"
            h2 = _re.search(r'(\d+\.\d+\.\d+\.\d+)', fpath)
            h2 = h2.group(1) if h2 else host
            add("high", f"FTP Service Banner Disclosure on {h2} — FileZilla Server {fz_v}",
                h2, "21", "ftp",
                f"FTP banner on {h2} reveals FileZilla Server version {fz_v}. Version disclosure enables targeted exploitation. FileZilla Server 0.9.x is legacy software. FTP banner also confirms the service is actively running.",
                content[:300],
                "1. Suppress FTP banner version in FileZilla Server settings. 2. Upgrade to FileZilla Server 1.x (current release). 3. Migrate to SFTP (SSH). 4. Disable FTP if not business-critical.")

        if "admin_nopass" in fname or ("331 password required for admin" in content_lower):
            h2 = _re.search(r'(\d+\.\d+\.\d+\.\d+)', fpath)
            h2 = h2.group(1) if h2 else host
            add("critical", f"FTP Default Admin Account Probed on {h2} — Authentication Challenge Present",
                h2, "21", "ftp",
                f"FTP probe confirms admin account exists on {h2} (server requested password for 'admin'). The existence of a named admin account with a known username enables targeted password attacks.",
                content,
                "1. Rename or disable default admin FTP account. 2. Enforce password complexity requirements. 3. Implement account lockout policy. 4. Migrate from FTP to SFTP.")

        if "anonymous_anonymous" in fname or ("331 password required for anonymous" in content_lower and "anonymous" in content_lower):
            h2 = _re.search(r'(\d+\.\d+\.\d+\.\d+)', fpath)
            h2 = h2.group(1) if h2 else host
            add("high", f"FTP Anonymous Account Probed on {h2}",
                h2, "21", "ftp",
                f"Anonymous FTP login was tested on {h2}. The server requested a password for anonymous access. Even requiring a password for anonymous logins is a security concern — anonymous access should be fully disabled.",
                content,
                "1. Disable anonymous FTP login completely. 2. Require named account authentication. 3. Migrate to SFTP.")

        if "ftp_test.log" in fname:
            # FTPS/TLS not detected
            if "ftps/tls not detected" in content_lower:
                ftps_hosts = _re.findall(r'ftps/tls not detected on (\S+)', content_lower)
                for fh in (ftps_hosts or [host])[:3]:
                    add("critical", f"FTPS/TLS Not Detected on {fh} — Cleartext FTP in Use",
                        fh.split(":")[0], "21", "ftp",
                        f"FTP testing confirmed FTPS/TLS is not enabled on {fh}. All FTP sessions including credentials, file listings, and file contents are transmitted in cleartext and are trivially interceptable.",
                        snip("ftps/tls"),
                        "1. Enable FTPS (FTP over TLS) on the server. 2. Require TLS for all connections (Explicit FTPS). 3. Ideally migrate to SFTP which uses SSH encryption.")

            # FileZilla detected via log
            if "filezilla" in content_lower:
                fz_hosts = _re.findall(r'confirmed filezilla server [\d\.]+ (?:beta )?on (\S+)', content_lower)
                for fzh in (fz_hosts or [host])[:3]:
                    h2 = fzh.split(":")[0]
                    add("high", f"FileZilla FTP Server Confirmed on {h2} — Version Disclosure",
                        h2, "21", "ftp",
                        f"FTP testing log confirms FileZilla Server is running on {h2}. FileZilla Server 0.9.x is end-of-life. Combined with no FTPS, all credentials transmitted to this server are in cleartext.",
                        snip("filezilla"),
                        "1. Upgrade FileZilla Server to 1.x. 2. Enable FTPS. 3. Migrate to SFTP long-term.")

        # ── Intelligent FTP MCP assessment ────────────────────────────────
        if "intelligent_ftp" in fname:
            h2 = _re.search(r'(\d+\.\d+\.\d+\.\d+)', fpath)
            h2 = h2.group(1) if h2 else host
            if "21/tcp" in content and "open" in content_lower:
                fz = _re.search(r'filezilla ftpd ([\d\.]+)', content_lower)
                fzv = fz.group(1) if fz else ""
                add("critical", f"FTP Service Confirmed Open on {h2}:21 — FileZilla ftpd {fzv}",
                    h2, "21", "ftp",
                    f"Intelligent MCP assessment confirms FTP (FileZilla ftpd {fzv}) is open on {h2}. Port 21 is accessible and the FTP daemon is actively responding. Combined with HTTP/HTTPS services, this host has multiple attack vectors.",
                    content[:500],
                    "1. Disable FTP port 21 — migrate to SFTP. 2. If FTP required, enable FTPS. 3. Firewall port 21 from all untrusted networks.")

            if "80/tcp" in content and "open" in content_lower:
                add("medium", f"HTTP Service Open on {h2}:80",
                    h2, "80", "http",
                    f"HTTP service on port 80 is confirmed on {h2}. Cleartext HTTP exposes sessions and credentials to interception. This host appears to be a multi-service server (FTP + HTTP).",
                    snip("80/tcp"),
                    "1. Redirect HTTP to HTTPS. 2. Enable HSTS. 3. Audit web application for vulnerabilities.")

        # ── DB2 targeted scan ─────────────────────────────────────────────
        if "db2" in fname:
            h2 = _re.search(r'(\d+\.\d+\.\d+\.\d+)', fpath)
            h2 = h2.group(1) if h2 else host
            if "open" in content_lower:
                add("critical", f"IBM DB2 Service Open on {h2}:50000",
                    h2, "50000", "db2",
                    f"IBM DB2 port 50000 is open on {h2}. DB2 exposed without strict network controls allows unauthenticated enumeration and exploitation. DB2 has a history of critical RCE vulnerabilities including CVE-2023-27555.",
                    content,
                    "1. Firewall DB2 port 50000 to application servers only. 2. Require strong authentication. 3. Apply latest IBM DB2 patches. 4. Disable DB2 remote connections if not required.")

        # ── SNMP targeted scan ────────────────────────────────────────────
        if "snmp" in fname:
            h2 = _re.search(r'(\d+\.\d+\.\d+\.\d+)', fpath)
            h2 = h2.group(1) if h2 else host
            if "timeout" in content_lower or "no response" in content_lower:
                add("medium", f"SNMP Probe Timed Out on {h2}:161 — Default Community String Not Valid",
                    h2, "161", "snmp",
                    f"SNMP enumeration against {h2} timed out or received no response. The default community string was not valid, but the SNMP service may still be running with non-default credentials. SNMP services are high-value targets.",
                    content,
                    "1. Identify if SNMP is running on this host. 2. If SNMP is present, migrate to SNMPv3. 3. Use custom community strings. 4. Restrict SNMP to management VLAN only.")

        # ── ssl_config.txt ────────────────────────────────────────────────
        if "ssl_config" in fname:
            # Strong config (least strength A) = still note for completeness
            clean_hosts = _re.findall(r'Nmap scan report for (\d+\.\d+\.\d+\.\d+)(?:.*\n)*?.*least strength: A', content)
            for ch in clean_hosts[:3]:
                add("low", f"SSL/TLS Configuration Assessed on {ch} — Least Strength: A",
                    ch, "443", "https",
                    f"Nmap ssl-enum-ciphers reports least cipher strength 'A' on {ch}. While this indicates good cipher configuration, ongoing monitoring is required as cipher recommendations evolve. Verify TLS 1.3 is offered.",
                    snip(ch),
                    "1. Verify TLS 1.3 is enabled. 2. Ensure only TLSv1.2 and TLSv1.3 are offered. 3. Schedule quarterly cipher review. 4. Monitor for new cipher deprecations.")

            # No TLS on HTTP port
            no_tls_sc = _re.findall(r'No TLS detected on (\d+\.\d+\.\d+\.\d+:\d+)', content)
            for nt in no_tls_sc[:5]:
                h2 = nt.split(":")[0]
                add("high", f"No TLS on {nt} — HTTP Service Running Without Encryption",
                    h2, nt.split(":")[1], "http",
                    f"ssl_config assessment confirms no TLS on {nt}. HTTP traffic including session cookies and POST data is transmitted in cleartext.",
                    snip(nt.split(":")[0]),
                    "1. Enable TLS on this service. 2. Redirect HTTP to HTTPS. 3. Implement HSTS header.")

        # ── TLS tests log ─────────────────────────────────────────────────
        if "tls_tests.log" in fname:
            tls_hosts = list(dict.fromkeys(_re.findall(r'testing (\d+\.\d+\.\d+\.\d+) for tls', content_lower)))
            if tls_hosts:
                add("medium", f"TLS/SSL Assessment Performed on {len(tls_hosts)} Hosts",
                    tls_hosts[0], "443", "https",
                    f"Automated TLS/SSL testing was conducted against {len(tls_hosts)} hosts: {', '.join(tls_hosts)}. TLS assessments check for weak ciphers, deprecated protocols, and certificate issues.",
                    "\n".join(tls_hosts),
                    "1. Review testssl.sh findings for each host. 2. Disable deprecated protocols (SSLv3, TLS 1.0, TLS 1.1). 3. Disable weak ciphers. 4. Enable TLS 1.3.")

        # ── WPScan analysis ───────────────────────────────────────────────
        if "wpscan" in fname or "wpscan" in content_lower:
            # PHP version
            php_ver = _re.search(r'x-powered-by: PHP/([\d\.]+)', content_lower)
            if php_ver:
                pv = php_ver.group(1)
                wp_host = _re.search(r'target: https?://([^\s/]+)', content_lower)
                h2 = wp_host.group(1) if wp_host else host
                add("high", f"PHP Version Disclosed on {h2}: PHP/{pv}",
                    h2, "443", "php",
                    f"WPScan detected PHP version {pv} disclosed via X-Powered-By header on {h2}. PHP {pv} may be end-of-life — PHP 7.4 reached EOL in November 2022. Disclosed version enables targeted PHP CVE exploitation.",
                    snip("php"),
                    f"1. Upgrade PHP to 8.2+ (current supported). 2. Remove X-Powered-By header: expose_php = Off in php.ini. 3. Review PHP security configuration.")

            if "access-control-allow-origin: *" in content_lower:
                wp_host = _re.search(r'target: https?://([^\s/]+)', content_lower)
                h2 = wp_host.group(1) if wp_host else host
                add("high", f"CORS Wildcard Origin (*) on {h2} — Cross-Origin Data Access",
                    h2, "443", "http",
                    f"WPScan detected Access-Control-Allow-Origin: * on {h2}. A wildcard CORS policy allows any website to make cross-origin requests and read responses, enabling data theft from authenticated sessions.",
                    snip("access-control-allow-origin"),
                    "1. Remove wildcard CORS. 2. Restrict CORS to specific trusted origins. 3. Implement pre-flight request validation.")

            if "wordpress readme" in content_lower:
                wp_host = _re.search(r'target: https?://([^\s/]+)', content_lower)
                h2 = wp_host.group(1) if wp_host else host
                add("medium", f"WordPress readme.html Publicly Accessible on {h2} — Version Disclosure",
                    h2, "443", "wordpress",
                    f"WordPress readme.html is publicly accessible on {h2}. This file discloses the WordPress version and provides information that helps attackers target known WordPress CVEs.",
                    snip("readme"),
                    "1. Delete or restrict access to readme.html, license.txt, and wp-config-sample.php. 2. Keep WordPress core updated.")

            if "wp-cron" in content_lower:
                wp_host = _re.search(r'target: https?://([^\s/]+)', content_lower)
                h2 = wp_host.group(1) if wp_host else host
                add("medium", f"WordPress WP-Cron Publicly Accessible on {h2} — DoS Risk",
                    h2, "443", "wordpress",
                    f"wp-cron.php is publicly accessible on {h2}. External WP-Cron can be abused by attackers to trigger resource-intensive scheduled tasks, causing denial of service.",
                    snip("wp-cron"),
                    "1. Disable external WP-Cron: define('DISABLE_WP_CRON', true) in wp-config.php. 2. Set up a real server cron job instead. 3. Block wp-cron.php via .htaccess or Nginx config.")

            if "must use plugins" in content_lower:
                wp_host = _re.search(r'target: https?://([^\s/]+)', content_lower)
                h2 = wp_host.group(1) if wp_host else host
                add("low", f"WordPress mu-plugins Directory Publicly Accessible on {h2}",
                    h2, "443", "wordpress",
                    f"WordPress mu-plugins directory is accessible on {h2}. Must-Use plugins run on every page load without activation. Exposed directory listing can reveal plugin names enabling targeted plugin vulnerability research.",
                    snip("mu-plugins"),
                    "1. Restrict directory listing: Options -Indexes in .htaccess. 2. Ensure mu-plugins are up to date. 3. Audit all mu-plugins for known CVEs.")

            if "robots.txt" in content_lower:
                wp_host = _re.search(r'target: https?://([^\s/]+)', content_lower)
                h2 = wp_host.group(1) if wp_host else host
                add("low", f"robots.txt Exposes Site Structure on {h2}",
                    h2, "443", "http",
                    f"WPScan discovered robots.txt on {h2}. robots.txt is publicly readable and often discloses sensitive paths that administrators want to hide from search engines — inadvertently advertising these paths to attackers.",
                    snip("robots.txt"),
                    "1. Review robots.txt for sensitive path disclosures. 2. Do not rely on robots.txt for security — secure paths with authentication instead. 3. Consider removing sensitive paths from robots.txt.")

            # WordPress version
            wp_ver = _re.search(r'wordpress version ([\d\.]+) identified', content_lower)
            if wp_ver:
                wv = wp_ver.group(1)
                wp_host = _re.search(r'target: https?://([^\s/]+)', content_lower)
                h2 = wp_host.group(1) if wp_host else host
                add("medium", f"WordPress {wv} Identified on {h2} — Version Disclosure",
                    h2, "443", "wordpress",
                    f"WPScan identified WordPress version {wv} on {h2}. Even the latest WordPress version has a known installation footprint. Version disclosure allows attackers to research version-specific vulnerabilities.",
                    snip("wordpress version"),
                    "1. Keep WordPress updated to latest version. 2. Remove version from generator meta tag and RSS feeds. 3. Implement a WAF to virtual-patch known WP vulnerabilities.")

        # ── WPScan analysis log (summary) ─────────────────────────────────
        if "wpscan_analysis.log" in fname:
            if "target:" in content_lower and ("finding" in content_lower or "interesting" in content_lower):
                wp_targets = list(dict.fromkeys(_re.findall(r'target: https?://(\S+)', content_lower)))
                add("medium", f"WordPress Security Scan Conducted Against {len(wp_targets)} Target(s)",
                    host or (wp_targets[0] if wp_targets else "WordPress"), "443", "wordpress",
                    f"WPScan security analysis was conducted against WordPress installations at: {', '.join(wp_targets[:3])}. WordPress sites are frequent targets for automated exploitation of plugin/theme vulnerabilities.",
                    content[:600],
                    "1. Regularly run WPScan against all WordPress installations. 2. Keep core, plugins, and themes updated. 3. Remove inactive plugins/themes. 4. Implement WordPress-specific WAF rules.")

