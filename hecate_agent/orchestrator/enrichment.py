import os
import re
import httpx
import logging
from typing import List, Dict


from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), "..", "..", ".env"))

def _setting(name: str, default: str = "") -> str:
    """Read a credential or endpoint from the environment (loaded from .env by the CLI).

    Never hardcode these: the values below were once committed and pushed.
    """
    return os.environ.get(name, default)


def _misp_verify_tls() -> bool:
    """Verify MISP's certificate unless MISP_VERIFY_SSL=false (e.g. a local self-signed instance)."""
    return _setting("MISP_VERIFY_SSL", "true").lower() != "false"

logger = logging.getLogger(__name__)


def extract_indicators(text: str) -> Dict[str, List[str]]:
    """Extract IPs, Domains, and Hashes from text using regex."""
    tlds = (
        r"com|org|net|io|ru|cn|info|biz|shop|top|xyz|site|online|club|vip|"
        r"live|app|dev|me|cc|co|pro|pw|win|work|cloud|space|link|click"
    )
    domain_re = rf'\b[a-zA-Z0-9.-]+\.(?:{tlds})\b'
    indicators = {
        "ips": list(set(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text))),
        "hashes": list(set(re.findall(r'\b[a-fA-F0-9]{32,64}\b', text))),
        "domains": list(set(re.findall(domain_re, text, re.IGNORECASE)))
    }
    # Filter out common false positives and private IPs
    indicators["ips"] = [
        ip for ip in indicators["ips"]
        if not ip.startswith((
            "127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
            "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
            "172.28.", "172.29.", "172.30.", "172.31.", "0.0.0.0", "255.255.255.255"
        ))
    ]
    benign_domains = {
        "github.com", "schemas.microsoft.com", "microsoft.com", "google.com",
        "virustotal.com", "alienvault.com", "abuse.ch", "mitre.org", "attack.mitre.org",
        "raw.githubusercontent.com", "api.github.com", "docs.microsoft.com",
        "learn.microsoft.com", "localhost"
    }
    indicators["domains"] = [
        d.lower() for d in indicators["domains"]
        if d.lower() not in benign_domains and not d.endswith(".local")
    ]
    return indicators

def query_vt_hash(file_hash: str) -> str:
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": _setting("VT_API_KEY")}
    try:
        resp = httpx.get(url, headers=headers, timeout=10.0)
        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            names = data.get("names", [])
            malicious = data.get("last_analysis_stats", {}).get("malicious", 0)
            threat_label = data.get("popular_threat_classification", {}).get("suggested_threat_label", "Unknown")
            return f"Malicious hits: {malicious} | Threat Label: {threat_label} | Known Filenames: {', '.join(names[:3])}"
        return "Not found or error."
    except Exception as e:
        return f"Error querying VT: {e}"

def query_vt_ip(ip: str) -> str:
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": _setting("VT_API_KEY")}
    try:
        resp = httpx.get(url, headers=headers, timeout=10.0)
        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            malicious = data.get("last_analysis_stats", {}).get("malicious", 0)
            asn = data.get("asn", "Unknown")
            owner = data.get("as_owner", "Unknown")
            return f"Malicious hits: {malicious} | ASN: {asn} | Owner: {owner}"
        return "Not found or error."
    except Exception as e:
        return f"Error querying VT: {e}"

def query_vt_domain(domain: str) -> str:
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": _setting("VT_API_KEY")}
    try:
        resp = httpx.get(url, headers=headers, timeout=10.0)
        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            malicious = data.get("last_analysis_stats", {}).get("malicious", 0)
            registrar = data.get("registrar", "Unknown")
            categories = data.get("categories", {})
            cat_sample = list(categories.values())[:2]
            cat_str = f" | Category: {', '.join(cat_sample)}" if cat_sample else ""
            return f"Malicious hits: {malicious} | Registrar: {registrar}{cat_str}"
        elif resp.status_code == 404:
            return "Domain not found on VirusTotal."
        return f"HTTP {resp.status_code}"
    except Exception as e:
        return f"Error querying VT: {e}"


def query_greynoise_ip(ip: str) -> str:
    key = _setting("GREYNOISE_API_KEY")
    if not key:
        return "GREYNOISE_API_KEY not configured."
    headers = {"key": key, "Accept": "application/json"}
    try:
        # Try v3 IP lookup endpoint first, fallback to v3 community endpoint
        url = f"https://api.greynoise.io/v3/ip/{ip}"
        resp = httpx.get(url, headers=headers, timeout=10.0)
        if resp.status_code == 404:
            return "No mass-internet scanning observed on GreyNoise (Unseen / Targeted)."
        elif resp.status_code in (401, 403):
            # Fallback to community endpoint for free-tier community keys
            comm_url = f"https://api.greynoise.io/v3/community/{ip}"
            resp = httpx.get(comm_url, headers=headers, timeout=10.0)
            if resp.status_code == 404:
                return "No mass-internet scanning observed on GreyNoise (Unseen / Targeted)."
            elif resp.status_code != 200:
                return f"GreyNoise Auth/API Error: {resp.status_code}"
        elif resp.status_code != 200:
            return f"GreyNoise API Error: {resp.status_code}"

        data = resp.json()
        bsi = data.get("business_service_intelligence") or {}
        isi = data.get("internet_scanner_intelligence") or {}
        riot = (bsi.get("found") is True) or data.get("riot", False)
        noise = (isi.get("found") is True) or data.get("noise", data.get("seen", False))
        classification = isi.get("classification") or data.get("classification") or "unknown"
        actor = isi.get("actor") or bsi.get("name") or data.get("actor") or data.get("name") or "Unknown"

        raw_tags = isi.get("tags") or data.get("tags") or []
        tags = []
        for t in raw_tags:
            if isinstance(t, str):
                tags.append(t)
            elif isinstance(t, dict) and t.get("name"):
                tags.append(t["name"])
        tag_str = f" | Tags: {', '.join(tags[:3])}" if tags else ""

        if riot:
            name = bsi.get("name") or actor
            trust = bsi.get("trust_level", "")
            trust_str = f" ({trust})" if trust else ""
            return f"RIOT: Benign Enterprise Service ({name}){trust_str} | Class: {classification}{tag_str}"
        elif noise:
            return f"Mass Internet Scanner ({classification}) | Actor: {actor}{tag_str}"
        elif classification and classification != "unknown":
            return f"Observed ({classification}) | Actor: {actor}{tag_str}"
        return "Not observed as scanner noise (Targeted or Inactive)."
    except Exception as e:
        return f"Error querying GreyNoise: {e}"




def query_shodan_ip(ip: str) -> str:
    url = f"https://api.shodan.io/shodan/host/{ip}?key={_setting('SHODAN_API_KEY')}"
    try:
        resp = httpx.get(url, timeout=10.0)
        if resp.status_code == 200:
            data = resp.json()
            org = data.get("org", "Unknown")
            os_name = data.get("os", "Unknown OS")
            ports = data.get("ports", [])
            vulns = data.get("vulns", [])
            
            summary = f"Org: {org} | OS: {os_name} | Open Ports: {ports}"
            if vulns:
                summary += f" | Vulns: {', '.join(vulns[:5])}"
            return summary
        elif resp.status_code == 404:
            return "No open ports found on Shodan."
        else:
            return f"Shodan API error: {resp.status_code}"
    except Exception as e:
        return f"Error querying Shodan: {e}"



def query_misp_indicator(indicator: str) -> str:
    url = f"{_setting('MISP_BASE_URL', 'https://localhost:8443')}/attributes/restSearch"
    headers = {
        "Authorization": _setting("MISP_API_KEY"),
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    data = {
        "value": indicator,
        "limit": 5
    }
    try:
        resp = httpx.post(url, headers=headers, json=data, verify=_misp_verify_tls(), timeout=10.0)
        if resp.status_code == 200:
            events = resp.json().get("response", {}).get("Attribute", [])
            if events:
                event_ids = list(set([str(e.get("event_id")) for e in events]))
                return f"Found in MISP Incident(s): {', '.join(event_ids[:3])}"
        return "Not seen in local MISP."
    except Exception as e:
        return f"Error querying MISP: {e}"


def expand_ttps(threat_intel: str) -> str:
    from hecate_agent.core.attack_matrix import _get_provider
    provider = _get_provider()
    
    try:
        if hasattr(provider, "_ensure_loaded"):
            provider._ensure_loaded()
            
        attack_data = getattr(provider, "_attack_data", None)
        if not attack_data:
            return ""
            
        software_list = attack_data.get_software(remove_revoked_deprecated=True)
        
        # Build a fast lookup of lowercase software names to their STIX objects
        software_map = {s.get("name", "").lower(): s for s in software_list if s.get("name")}
        
        found_software = []
        for soft_name, soft_obj in software_map.items():
            if len(soft_name) > 3 and soft_name in threat_intel.lower():
                found_software.append(soft_obj)
                
        if not found_software:
            return ""
            
        summary = ["\n### 🗺️ Automated TTP Expansion (MITRE ATT&CK STIX)"]
        for s in found_software[:3]:  # Limit to 3 to avoid massive context bloat
            techs = attack_data.get_techniques_used_by_software(s["id"])
            
            # Get external ATT&CK IDs
            tech_ids = []
            for t in techs:
                tech_obj = t.get("object")
                if tech_obj and tech_obj.get("external_references"):
                    for ref in tech_obj["external_references"]:
                        if ref.get("source_name") == "mitre-attack":
                            tech_ids.append(ref["external_id"])
                            break
                            
            if tech_ids:
                summary.append(f"- **{s.get('name')}**: Commonly uses {len(tech_ids)} techniques (e.g., {', '.join(tech_ids[:5])})")
                
        if len(summary) > 1:
            return "\n".join(summary)
        return ""
    except Exception as e:
        logger.error(f"STIX TTP Expansion error: {e}")
        return ""



def query_censys_ip(ip: str) -> str:
    url = f"https://api.platform.censys.io/v3/global/asset/host/{ip}"
    headers = {
        "Accept": "application/vnd.censys.api.v3.host.v1+json",
        "Authorization": f"Bearer {_setting('CENSYS_API_TOKEN')}"
    }
    try:
        resp = httpx.get(url, headers=headers, timeout=10.0)
        if resp.status_code == 200:
            result = resp.json().get("result", {})
            data = result.get("resource", result)
            services = data.get("services", [])
            ports = [str(s.get("port")) for s in services if s.get("port")]
            
            # Extract software
            software_list = []
            for s in services:
                if s.get("software"):
                    for sw in s["software"]:
                        product = sw.get("product")
                        if product and product not in software_list:
                            software_list.append(product)
                            
            summary = f"Open Ports: {ports}"
            if software_list:
                summary += f" | Software: {', '.join(software_list[:5])}"
            return summary
        elif resp.status_code == 401:
            return "Censys Auth Error (check token format)."
        elif resp.status_code == 404:
            return "No data on Censys."
        else:
            return f"Censys API error: {resp.status_code}"
    except Exception as e:
        return f"Error querying Censys: {e}"



def query_threatfox(indicator: str) -> str:
    url = "https://threatfox-api.abuse.ch/api/v1/"
    headers = {
        "Auth-Key": _setting("ABUSECH_API_KEY"),
        "Content-Type": "application/json"
    }
    payload = {
        "query": "search_ioc",
        "search_term": indicator
    }
    try:
        resp = httpx.post(url, headers=headers, json=payload, timeout=10.0)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("query_status") == "ok" and data.get("data"):
                hits = data["data"]
                # Get the most recent threat type and malware alias
                threat_type = hits[0].get("threat_type", "Unknown")
                malware = hits[0].get("malware_printable", "Unknown Malware")
                tags = hits[0].get("tags", [])
                
                summary = f"Type: {threat_type} | Malware: {malware}"
                if tags:
                    summary += f" | Tags: {', '.join(tags[:3])}"
                return summary
            elif data.get("query_status") == "no_result":
                return "No results on ThreatFox."
            else:
                return f"ThreatFox error: {data.get('query_status')}"
        return f"HTTP {resp.status_code}"
    except Exception as e:
        return f"Error querying ThreatFox: {e}"

def generate_enrichment_summary(threat_intel: str) -> str:
    """Extracts indicators and queries VT, returning a markdown summary."""
    indicators = extract_indicators(threat_intel)
    if not any(indicators.values()):
        return ""
        
    summary = ["\n\n### 🛡️ Automated Threat Enrichment (VT, GreyNoise, Shodan, Censys, Abuse.ch & MISP)"]
    
    from concurrent.futures import ThreadPoolExecutor
    
    def process_hash(h: str) -> str:
        res = query_vt_hash(h)
        misp_res = query_misp_indicator(h)
        threatfox_res = query_threatfox(h)
        return f"- **Hash {h}**:\n  - *VirusTotal:* {res}\n  - *Abuse.ch (ThreatFox):* {threatfox_res}\n  - *Internal MISP:* {misp_res}"

    def process_ip(ip: str) -> str:
        vt_res = query_vt_ip(ip)
        gn_res = query_greynoise_ip(ip)
        shodan_res = query_shodan_ip(ip)
        censys_res = query_censys_ip(ip)
        misp_res = query_misp_indicator(ip)
        threatfox_res = query_threatfox(ip)
        return (
            f"- **IP {ip}**:\n"
            f"  - *VirusTotal:* {vt_res}\n"
            f"  - *GreyNoise:* {gn_res}\n"
            f"  - *Shodan:* {shodan_res}\n"
            f"  - *Censys:* {censys_res}\n"
            f"  - *Abuse.ch (ThreatFox):* {threatfox_res}\n"
            f"  - *Internal MISP:* {misp_res}"
        )

    def process_domain(d: str) -> str:
        vt_res = query_vt_domain(d)
        misp_res = query_misp_indicator(d)
        threatfox_res = query_threatfox(d)
        return f"- **Domain {d}**:\n  - *VirusTotal:* {vt_res}\n  - *Abuse.ch (ThreatFox):* {threatfox_res}\n  - *Internal MISP:* {misp_res}"

    with ThreadPoolExecutor(max_workers=10) as executor:
        hash_futures = {executor.submit(process_hash, h): h for h in indicators["hashes"][:5]}
        ip_futures = {executor.submit(process_ip, ip): ip for ip in indicators["ips"][:5]}
        domain_futures = {executor.submit(process_domain, d): d for d in indicators["domains"][:5]}

        # To maintain order
        hash_results = {future: future.result() for future in hash_futures}
        for h in indicators["hashes"][:5]:
            for future, result in hash_results.items():
                if hash_futures[future] == h:
                    summary.append(result)
                    break

        ip_results = {future: future.result() for future in ip_futures}
        for ip in indicators["ips"][:5]:
            for future, result in ip_results.items():
                if ip_futures[future] == ip:
                    summary.append(result)
                    break

        domain_results = {future: future.result() for future in domain_futures}
        for d in indicators["domains"][:5]:
            for future, result in domain_results.items():
                if domain_futures[future] == d:
                    summary.append(result)
                    break
    
    final_output = ""
    if len(summary) > 1:
        final_output += "\n".join(summary)
        
    ttp_summary = expand_ttps(threat_intel)
    if ttp_summary:
        final_output += "\n" + ttp_summary
        
    return final_output
