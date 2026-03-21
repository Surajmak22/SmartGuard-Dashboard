"""
Upgraded Heuristic Scanner — SmartGuard AI
==========================================
100+ curated regex patterns across 10 threat categories.
Each pattern is weighted by real-world severity.
"""
from __future__ import annotations

import re
from typing import Dict, List, Tuple


class HeuristicScanner:
    """
    Layer 3: Heuristic analysis.
    Pattern-based detection covering 10 threat categories with 100+ signatures.
    Operates on raw bytes decoded to string (covers both text and binary content).
    """

    # Format: (regex_pattern, score_per_hit, human_description)
    PATTERN_CATEGORIES: Dict[str, List[Tuple[str, int, str]]] = {

        # ── PDF-Specific Exploits ────────────────────────────────────────────
        "PDF Exploits": [
            (r"\/JavaScript\s", 40, "PDF /JavaScript action key"),
            (r"\/JS\s*<<", 35, "PDF /JS inline action"),
            (r"\/OpenAction\s", 40, "PDF OpenAction — auto-executes on open"),
            (r"\/Launch\s", 50, "PDF /Launch action — runs external commands"),
            (r"\/AA\s*<<", 30, "PDF Additional Actions"),
            (r"\/EmbeddedFile\s", 35, "PDF embedded file object"),
            (r"\/XFA\s", 30, "PDF XFA forms — can embed scripts"),
            (r"\/RichMedia\s", 25, "PDF RichMedia — exploited Flash CVEs"),
            (r"util\.printf\s*\(", 50, "util.printf buffer overflow (CVE-2008-2992)"),
            (r"Collab\.collectEmailInfo", 55, "Collab.collectEmailInfo Adobe RCE exploit"),
            (r"app\.openDoc\s*\(", 35, "PDF openDoc — opens external files"),
            (r"this\.exportDataObject", 45, "exportDataObject — extracts embedded files"),
            (r"app\.doc\.syncAnnotScan", 40, "syncAnnotScan exploit chain"),
            (r"getAnnots\s*\(", 30, "getAnnots exploit vector"),
        ],

        # ── JavaScript / Code Execution ──────────────────────────────────────
        "JavaScript / Code Execution": [
            (r"\beval\s*\(", 35, "eval() — dynamic code execution"),
            (r"\bunescape\s*\(", 30, "unescape() — hex/URL payload decoding"),
            (r"String\.fromCharCode\s*\(", 25, "fromCharCode — character obfuscation"),
            (r"document\.write\s*\(", 20, "document.write() — DOM injection"),
            (r"document\.location\s*=", 25, "document.location redirect — phishing"),
            (r"\bsetTimeout\s*\(", 15, "setTimeout with code string — deferred execution"),
            (r"\bsetInterval\s*\(", 15, "setInterval — repeated execution"),
            (r"window\.location\.href\s*=", 20, "Location redirect"),
            (r"atob\s*\(", 25, "atob() — base64 decode in browser"),
            (r"Function\s*\(\s*['\"]", 30, "Function() constructor — code from string"),
            (r"ActiveXObject\s*\(", 40, "ActiveX — Windows-only exploit vector"),
            (r"WScript\.Shell", 55, "WScript.Shell — direct OS command execution"),
            (r"Shell\.Application", 50, "Shell.Application COM object"),
            (r"Scripting\.FileSystemObject", 35, "FileSystemObject — filesystem access"),
        ],

        # ── Shell / OS Command Execution ────────────────────────────────────
        "Shell / OS Command Execution": [
            (r"\bcmd\.exe\b", 45, "cmd.exe reference"),
            (r"\bpowershell\b", 40, "PowerShell reference"),
            (r"/bin/sh\b", 40, "POSIX shell reference"),
            (r"/bin/bash\b", 40, "Bash shell reference"),
            (r"\bshell_exec\s*\(", 50, "PHP shell_exec() — remote code execution"),
            (r"\bsystem\s*\(", 40, "system() call — OS command execution"),
            (r"\bpassthru\s*\(", 45, "PHP passthru() — raw command output"),
            (r"\bexec\s*\(", 35, "exec() call"),
            (r"\bpopen\s*\(", 35, "popen() — piped command"),
            (r"\bproc_open\s*\(", 40, "PHP proc_open()"),
            (r"subprocess\.call\s*\(", 30, "Python subprocess.call"),
            (r"os\.system\s*\(", 30, "Python os.system()"),
            (r"Runtime\.getRuntime\(\)\.exec", 45, "Java Runtime.exec() — remote code execution"),
            (r"\bnet\s+user\b", 40, "net user command — user account manipulation"),
            (r"\bnetsh\b", 30, "netsh — Windows firewall/network manipulation"),
            (r"\breg\s+add\b", 35, "Registry add — persistence mechanism"),
            (r"\bschtasks\b", 35, "schtasks — scheduled task creation (persistence)"),
            (r"\bat\s+\\\\\b", 30, "at command — remote scheduled task"),
            (r"taskkill\s*/f\b", 25, "taskkill /f — forceful process termination"),
        ],

        # ── Obfuscation Indicators ───────────────────────────────────────────
        "Obfuscation": [
            (r"base64_decode\s*\(", 30, "PHP base64_decode — encoded payload"),
            (r"[A-Za-z0-9+/]{80,}={0,2}", 20, "Long base64 string (80+ chars) — encoded content"),
            (r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){8,}", 35, "Long hex escape sequence — shellcode encoding"),
            (r"chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+", 25, "chr() chaining — character-level obfuscation"),
            (r"\\u[0-9a-fA-F]{4}(\\u[0-9a-fA-F]{4}){5,}", 25, "Unicode escape sequence chain"),
            (r"(?:[0-9a-fA-F]{2}\s+){16,}", 25, "Raw hex dump pattern — potential shellcode"),
            (r"gzinflate\s*\(", 30, "PHP gzinflate — compressed payload unpacking"),
            (r"gzuncompress\s*\(", 30, "PHP gzuncompress — compressed payload"),
            (r"str_rot13\s*\(", 20, "ROT13 encoding — lightweight obfuscation"),
            (r"strrev\s*\(", 15, "strrev — reversed string obfuscation"),
            (r"preg_replace\s*\(.+\/e[imsxADSUXJ]*['\"]", 45, "PHP preg_replace /e modifier — code execution"),
        ],

        # ── Network / C2 Indicators ──────────────────────────────────────────
        "Network / C2": [
            (r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", 35, "HTTP to raw IP — typical C2 server pattern"),
            (r"https?://[^/\s]{4,}\.(xyz|top|tk|ml|ga|cf|gq|pw)/", 30, "HTTP to suspicious TLD (.xyz/.tk/.ml etc.)"),
            (r"URLDownloadToFile\s*\(", 45, "URLDownloadToFile — downloads executable"),
            (r"InternetOpenUrl\s*\(", 30, "InternetOpenUrl — HTTP connection from PE"),
            (r"socket\s*\.\s*connect\s*\(", 25, "Raw socket connect — potential RAT/backdoor"),
            (r"ftp://[^\s]{5,}", 25, "FTP URL — potential data exfiltration"),
            (r"\\\\[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\\", 30, "UNC path to IP — lateral movement / SMB"),
            (r"nc\s+-[lnvep]+\s+\d{2,5}", 40, "Netcat listener command — reverse shell"),
            (r"/dev/tcp/", 45, "Bash /dev/tcp — shell reverse connection"),
            (r"curl\s+.{0,30}\|\s*bash", 55, "curl pipe to bash — one-liner dropper"),
            (r"wget\s+.{0,30}\|\s*sh\b", 55, "wget pipe to shell — one-liner dropper"),
        ],

        # ── Privilege Escalation / Persistence ──────────────────────────────
        "Privilege Escalation / Persistence": [
            (r"sudo\s+-S\b", 35, "sudo -S — reads password from stdin (automation)"),
            (r"chmod\s+[0-7]*7[0-7]{2,}", 25, "chmod with execute bits — making file executable"),
            (r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 40, "Registry Run key — startup persistence"),
            (r"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 35, "HKCU Run key — user-level persistence"),
            (r"crontab\s+-[el]", 30, "crontab modification — cron persistence"),
            (r"/etc/cron\.", 30, "Writing to cron directory — persistence"),
            (r"useradd\b.{0,30}-p\b", 40, "useradd with password — backdoor account"),
            (r"net\s+localgroup\s+administrators", 45, "Adding to admin group — privilege escalation"),
            (r"runas\b.{0,40}/user:administrator", 35, "runas as administrator"),
            (r"SeDebugPrivilege", 40, "SE_DEBUG privilege — required for process injection"),
        ],

        # ── Anti-Analysis / Evasion ──────────────────────────────────────────
        "Anti-Analysis / Sandbox Evasion": [
            (r"IsDebuggerPresent\b", 35, "Anti-debug check — detects analysis environments"),
            (r"CheckRemoteDebuggerPresent\b", 35, "Remote debugger detection"),
            (r"NtQueryInformationProcess\b", 30, "NT query — check for debugger attachment"),
            (r"GetTickCount\b", 15, "GetTickCount timing — sandbox stalling detection"),
            (r"Sleep\s*\(\s*[0-9]{5,}", 20, "Long Sleep() — sandbox timeout evasion"),
            (r"VBOX|VirtualBox|VMware|QEMU|Hyper-V", 30, "VM/sandbox detection strings"),
            (r"SANDBOX|maltest|cuckoo|wireshark", 25, "Common sandbox environment strings"),
            (r"GetModuleHandle\s*\(\s*['\"]SbieDll", 35, "Sandboxie detection — evades sandboxed analysis"),
            (r"OutputDebugString\b", 10, "OutputDebugString — timing-based anti-debug"),
        ],

        # ── Macro / VBA / Office Exploits ────────────────────────────────────
        "Office / Macro Exploits": [
            (r"\bAutoOpen\b", 40, "VBA AutoOpen macro — auto-executes on document open"),
            (r"\bDocument_Open\b", 40, "Document_Open event — macro auto-execution"),
            (r"\bAuto_Open\b", 40, "Auto_Open — Excel auto-execute macro"),
            (r"\bWorkbook_Open\b", 35, "Workbook_Open — Excel auto-execute"),
            (r"\bShell\s*\(", 35, "VBA Shell() — executes OS commands"),
            (r"CreateObject\s*\(\s*['\"]WScript\.Shell", 45, "VBA WScript.Shell creation"),
            (r"CreateObject\s*\(\s*['\"]MSXML2\.XMLHTTP", 35, "VBA HTTP request — downloads payload"),
            (r"Environ\s*\(\s*['\"]APPDATA", 20, "Reading APPDATA path — file drop location"),
            (r"DDEAUTO\b", 50, "DDE Auto — executes commands without macros"),
            (r"mshta\b.{0,60}http", 50, "mshta fetching remote HTA — common dropper"),
            (r"regsvr32\b.{0,60}/s\b.{0,60}/u\b", 45, "regsvr32 COM scriptlet — AppLocker bypass"),
        ],

        # ── Credential Harvesting ────────────────────────────────────────────
        "Credential Harvesting": [
            (r"mimikatz", 70, "Mimikatz — credential dumping tool"),
            (r"sekurlsa::logonpasswords", 75, "Mimikatz command — dumps logon passwords"),
            (r"lsass\.exe", 40, "LSASS process reference — credential store"),
            (r"SAM\s+database\b", 35, "SAM database — Windows credential store"),
            (r"hashdump\b", 50, "hashdump — Metasploit credential dump"),
            (r"GetPasswordHash\b", 35, "Password hash retrieval"),
            (r"CredEnumerate\s*\(", 30, "CredEnumerate — reads stored credentials"),
            (r"CryptUnprotectData\s*\(", 25, "CryptUnprotectData — decrypts DPAPI secrets"),
            (r"keylogger|keystroke.{0,10}captur", 40, "Keylogger reference"),
            (r"GetAsyncKeyState\s*\(", 35, "GetAsyncKeyState — keyboard hook (keylogger API)"),
        ],

        # ── Ransomware Indicators ────────────────────────────────────────────
        "Ransomware Indicators": [
            (r"CryptEncrypt\s*\(", 30, "CryptEncrypt — file encryption API"),
            (r"CryptGenKey\s*\(", 25, "CryptGenKey — generates encryption keys"),
            (r"FindFirstFile\s*\(\s*['\"][*]", 20, "Recursive file enumeration — mass file access"),
            (r"\.locked|\.encrypted|\.crypt\b", 35, "Ransomware extension patterns"),
            (r"YOUR_FILES_ARE_ENCRYPTED|pay.*bitcoin|ransom", 60, "Ransomware ransom note text"),
            (r"DeleteShadowCopy|vssadmin.*delete", 65, "VSS deletion — destroys file backups before encryption"),
            (r"bcdedit\s+/set.{0,30}recoveryenabled\s+no", 65, "Disabling Windows recovery — ransomware prep"),
            (r"wbadmin\s+delete\s+catalog", 60, "Deleting backup catalog — ransomware prep"),
        ],
    }

    def scan(self, file_data: bytes, filename: str) -> Dict:
        threats: List[str] = []
        risk_score = 0

        # Decode bytes to string — errors='replace' so we don't miss binary-encoded text
        content_str = file_data.decode("utf-8", errors="replace")
        # Also search filename
        search_target = content_str + " " + filename

        category_hits: Dict[str, int] = {}

        for category, patterns in self.PATTERN_CATEGORIES.items():
            cat_score = 0
            cat_matches: List[str] = []

            for pattern, score, desc in patterns:
                try:
                    if re.search(pattern, search_target, re.IGNORECASE):
                        cat_score += score
                        cat_matches.append(desc)
                except re.error:
                    pass

            if cat_matches:
                # Cap per-category contribution to prevent runaway scoring
                capped = min(cat_score, 80)
                risk_score += capped
                category_hits[category] = len(cat_matches)

                # Show the top 3 matches per category
                summary = f"[{category}] {len(cat_matches)} pattern(s) matched — "
                summary += "; ".join(cat_matches[:3])
                if len(cat_matches) > 3:
                    summary += f" ... (+{len(cat_matches) - 3} more)"
                threats.append(summary)

        return {
            "threats": threats,
            "risk_score": min(risk_score, 100),
            "category_hits": category_hits,
            "layer": "Heuristic",
        }
