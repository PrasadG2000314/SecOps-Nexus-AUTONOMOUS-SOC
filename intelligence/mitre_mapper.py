"""
MITRE ATT&CK & CISA KEV Security Taxonomy
Enriches incoming alerts with adversary tactics, techniques, and real-world exploitation intel.
"""
from typing import Dict, List, Any, Optional

MITRE_TECHNIQUES = {
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "TA0001 Initial Access",
        "description": "Adversaries may attempt to exploit a weakness in an Internet-facing computer or program."
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "TA0002 Execution",
        "description": "Adversaries may abuse command and script interpreters to execute arbitrary commands."
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "TA0005 Defense Evasion / TA0003 Persistence",
        "description": "Adversaries may obtain and abuse credentials of existing accounts."
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "TA0006 Credential Access",
        "description": "Adversaries may use brute force techniques to attempt credential guessing or password spraying."
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "TA0007 Discovery",
        "description": "Adversaries may attempt to get a listing of other systems by IP address, hostname, or network services."
    },
    "T1021": {
        "name": "Remote Services",
        "tactic": "TA0008 Lateral Movement",
        "description": "Adversaries may use Valid Accounts to log into a service specifically designed to accept remote connections."
    },
    "T1499": {
        "name": "Endpoint Denial of Service",
        "tactic": "TA0040 Impact",
        "description": "Adversaries may perform Endpoint Denial of Service to degrade or block the availability of services."
    },
    "T1195": {
        "name": "Supply Chain Compromise",
        "tactic": "TA0001 Initial Access",
        "description": "Adversaries may manipulate products or product delivery mechanisms prior to receipt."
    }
}

# Real-world CISA Known Exploited Vulnerabilities catalog subset
KNOWN_EXPLOITED_CVE_CATALOG = {
    "CVE-2024-3094": {
        "vendor": "XZ / Liblzma",
        "product": "xz-utils",
        "description": "Malicious code discovered in upstream xz/liblzma resulting in unauthorized SSH bypass and RCE.",
        "due_date": "2024-04-10",
        "notes": "Backdoor targeting OpenSSH daemon via systemd integration."
    },
    "CVE-2021-44228": {
        "vendor": "Apache",
        "product": "Log4j2",
        "description": "Remote Code Execution via JNDI lookup vulnerability in Log4j.",
        "due_date": "2021-12-24",
        "notes": "Massively exploited in the wild across enterprise software."
    },
    "CVE-2023-4863": {
        "vendor": "Google / WebP",
        "product": "libwebp",
        "description": "Heap buffer overflow in WebP codec permitting arbitrary code execution.",
        "due_date": "2023-10-04",
        "notes": "Zero-day exploited in targeted attacks."
    },
    "CVE-2023-38606": {
        "vendor": "Apple",
        "product": "Kernel",
        "description": "Memory corruption vulnerability allowing kernel code execution.",
        "due_date": "2023-08-14",
        "notes": "Operation Triangulation zero-click exploit."
    }
}

class MitreAttackCatalog:
    def map_vulnerability(self, cve_id: Optional[str], cwe_id: Optional[str], title: str) -> Dict[str, Any]:
        """
        Maps a vulnerability to relevant MITRE ATT&CK tactics and techniques.
        """
        tactics: List[str] = []
        techniques: List[str] = []

        t_lower = title.lower()
        if "sql" in t_lower or "injection" in t_lower or "cwe-89" in str(cwe_id).lower():
            techniques.append("T1190 Exploit Public-Facing Application")
            tactics.append("TA0001 Initial Access")
        elif "brute" in t_lower or "cwe-307" in str(cwe_id).lower():
            techniques.append("T1110 Brute Force")
            tactics.append("TA0006 Credential Access")
        elif "backdoor" in t_lower or cve_id == "CVE-2024-3094":
            techniques.append("T1195 Supply Chain Compromise")
            techniques.append("T1190 Exploit Public-Facing Application")
            tactics.append("TA0001 Initial Access")
            tactics.append("TA0005 Defense Evasion")
        elif "open port" in t_lower or "rdp" in t_lower:
            techniques.append("T1046 Network Service Discovery")
            techniques.append("T1021 Remote Services")
            tactics.append("TA0007 Discovery")
            tactics.append("TA0008 Lateral Movement")
        else:
            techniques.append("T1190 Exploit Public-Facing Application")
            tactics.append("TA0001 Initial Access")

        return {
            "tactics": list(set(tactics)),
            "techniques": list(set(techniques))
        }

    def check_cisa_kev(self, cve_id: Optional[str]) -> Optional[Dict[str, Any]]:
        """Checks if the CVE is in CISA KEV catalog."""
        if not cve_id:
            return None
        return KNOWN_EXPLOITED_CVE_CATALOG.get(cve_id.upper())

mitre_catalog = MitreAttackCatalog()
