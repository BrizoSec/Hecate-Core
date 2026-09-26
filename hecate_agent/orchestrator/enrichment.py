import re
import httpx
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

VT_API_KEY = "***REMOVED***"

def extract_indicators(text: str) -> Dict[str, List[str]]:
    """Extract IPs, Domains, and Hashes from text using regex."""
    indicators = {
        "ips": list(set(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text))),
        "hashes": list(set(re.findall(r'\b[a-fA-F0-9]{32,64}\b', text))),
        # Simple domain regex for common TLDs
        "domains": list(set(re.findall(r'\b[a-zA-Z0-9.-]+\.(?:com|org|net|io|ru|cn|info|biz)\b', text)))
    }
    # Filter out common false positives
    indicators["ips"] = [ip for ip in indicators["ips"] if not ip.startswith(("127.", "10.", "192.168.", "172.16."))]
    return indicators

def query_vt_hash(file_hash: str) -> str:
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}
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
    headers = {"x-apikey": VT_API_KEY}
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


SHODAN_API_KEY = "***REMOVED***"

def query_shodan_ip(ip: str) -> str:
    url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
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


MISP_BASE_URL = "https://localhost:8443"
MISP_API_KEY = "***REMOVED***"

def query_misp_indicator(indicator: str) -> str:
    url = f"{MISP_BASE_URL}/attributes/restSearch"
    headers = {
        "Authorization": MISP_API_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    data = {
        "value": indicator,
        "limit": 5
    }
    try:
        resp = httpx.post(url, headers=headers, json=data, verify=False, timeout=10.0)
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


CENSYS_TOKEN = "***REMOVED***"

def query_censys_ip(ip: str) -> str:
    url = f"https://search.censys.io/api/v2/hosts/{ip}"
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {CENSYS_TOKEN}"
    }
    try:
        resp = httpx.get(url, headers=headers, timeout=10.0)
        if resp.status_code == 200:
            data = resp.json().get("result", {})
            services = data.get("services", [])
            ports = [str(s.get("port")) for s in services]
            
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


ABUSECH_API_KEY = "***REMOVED***"

def query_threatfox(indicator: str) -> str:
    url = "https://threatfox-api.abuse.ch/api/v1/"
    headers = {
        "API-KEY": ABUSECH_API_KEY,
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
        
    summary = ["\n\n### 🛡️ Automated Threat Enrichment (VT, Shodan, Censys, Abuse.ch & MISP)"]
    
    for h in indicators["hashes"][:5]:  # Limit to 5 to save API quota/time
        res = query_vt_hash(h)
        misp_res = query_misp_indicator(h)
        threatfox_res = query_threatfox(h)
        summary.append(f"- **Hash {h}**:\n  - *VirusTotal:* {res}\n  - *Abuse.ch (ThreatFox):* {threatfox_res}\n  - *Internal MISP:* {misp_res}")
        
    for ip in indicators["ips"][:5]:
        vt_res = query_vt_ip(ip)
        shodan_res = query_shodan_ip(ip)
        censys_res = query_censys_ip(ip)
        misp_res = query_misp_indicator(ip)
        threatfox_res = query_threatfox(ip)
        summary.append(f"- **IP {ip}**:\n  - *VirusTotal:* {vt_res}\n  - *Shodan:* {shodan_res}\n  - *Censys:* {censys_res}\n  - *Abuse.ch (ThreatFox):* {threatfox_res}\n  - *Internal MISP:* {misp_res}")
        
    # Exclude domains to keep it fast, or add domain endpoint if needed
    
    final_output = ""
    if len(summary) > 1:
        final_output += "\n".join(summary)
        
    ttp_summary = expand_ttps(threat_intel)
    if ttp_summary:
        final_output += "\n" + ttp_summary
        
    return final_output
