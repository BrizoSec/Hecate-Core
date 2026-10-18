import os
import re
import httpx
import logging
from datetime import datetime, timezone
from typing import List, Dict, Set


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


def refang(value: str) -> str:
    """Undo report defanging ("hxxp", "[.]", "(.)", "[:]", "(:)", etc.) so values match real telemetry."""
    if not value or not isinstance(value, str):
        return ""
    v = value.replace("[.]", ".").replace("(.)", ".").replace("[dot]", ".").replace("(dot)", ".")
    v = v.replace("[:]", ":").replace("(:)", ":")
    return re.sub(r"\bhxxp", "http", v, flags=re.IGNORECASE)


def _get_apex_domain(domain: str) -> str:
    """Extract registrable apex domain (e.g. c2.evil.com -> evil.com)."""
    parts = domain.lower().strip(".").split(".")
    if len(parts) <= 2:
        return domain
    two_part_tlds = {
        "co.uk", "gov.uk", "ac.uk", "org.uk", "com.au", "net.au", "co.nz",
        "co.jp", "com.kg", "org.kg", "net.kg", "com.cn", "net.cn", "org.cn",
        "gov.cn", "com.br", "co.in", "com.tr", "co.za", "com.mx", "com.ar",
    }
    last_two = f"{parts[-2]}.{parts[-1]}"
    if last_two in two_part_tlds and len(parts) > 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


_KNOWN_PUBLISHER_DOMAINS: Set[str] = {
    # Platform / code / vendor repositories and schemas
    "github.com", "schemas.microsoft.com", "microsoft.com", "google.com",
    "raw.githubusercontent.com", "api.github.com", "docs.microsoft.com",
    "learn.microsoft.com", "localhost",
    # Intelligence providers, sandboxes, OSINT & scanners
    "virustotal.com", "alienvault.com", "abuse.ch", "mitre.org", "attack.mitre.org",
    "shodan.io", "censys.io", "greynoise.io", "abuseipdb.com", "threatfox.abuse.ch",
    "urlhaus.abuse.ch", "malwarebazaar.abuse.ch", "feodotracker.abuse.ch",
    # Major cybersecurity vendors and threat research publishers
    "blackpointcyber.com", "mandiant.com", "crowdstrike.com", "paloaltonetworks.com",
    "sentinelone.com", "bleepingcomputer.com", "thehackernews.com", "recordedfuture.com",
    "redcanary.com", "trendmicro.com", "trellix.com", "kaspersky.com", "securelist.com",
    "talosintelligence.com", "cisco.com", "proofpoint.com", "symantec.com", "broadcom.com",
    "sophos.com", "fireeye.com", "elastic.co", "rapid7.com", "cybereason.com", "dragos.com",
    "welivesecurity.com", "eset.com", "darkreading.com", "securityweek.com",
    "krebsonsecurity.com", "cisa.gov", "ncsc.gov.uk", "cert.europa.eu", "circl.lu",
    "socradar.io", "volexity.com", "huntress.com", "group-ib.com", "fortinet.com",
    "checkpoint.com", "blackberry.com", "qualys.com", "tenable.com", "snyk.io", "github.blog",
}


def extract_indicators(text: str) -> Dict[str, List[str]]:
    """Extract IPs, Domains, and Hashes from text using regex, refanging first."""
    if not text:
        return {"ips": [], "hashes": [], "domains": []}
    clean_text = refang(text)
    tlds_list = [
        r"co\.uk", r"gov\.uk", r"ac\.uk", r"org\.uk", r"com\.au", r"net\.au",
        r"co\.nz", r"co\.jp", r"com\.kg", r"org\.kg", r"net\.kg", r"com\.cn",
        r"net\.cn", r"org\.cn", r"gov\.cn", r"com\.br", r"co\.in", r"com\.tr",
        r"co\.za", r"com\.mx", r"com\.ar",
        r"com", r"org", r"net", r"edu", r"gov", r"mil", r"info", r"biz",
        r"shop", r"top", r"xyz", r"site", r"online", r"club", r"vip", r"live",
        r"app", r"dev", r"pro", r"win", r"work", r"cloud", r"space", r"link", r"one",
        r"click", r"tech", r"store", r"news", r"blog", r"icu", r"fun", r"digital",
        r"security", r"agency", r"center",
        r"io", r"ai", r"me", r"cc", r"tv", r"to", r"is", r"pw", r"ws",
        r"uk", r"de", r"cn", r"ru", r"jp", r"kr", r"in", r"br", r"ca", r"au",
        r"fr", r"nl", r"se", r"no", r"fi", r"es", r"it", r"pl", r"ch", r"at",
        r"be", r"cz", r"ro", r"ua", r"za", r"mx", r"ar", r"cl", r"co", r"id",
        r"my", r"th", r"vn", r"ph", r"sg", r"nz", r"kg"
    ]
    tlds = "|".join(tlds_list)
    domain_re = rf'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{{0,61}}[a-zA-Z0-9])?\.)+(?:{tlds})\b(?!\.[a-zA-Z0-9])'
    indicators = {
        "ips": list(set(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', clean_text))),
        "hashes": list(set(re.findall(r'\b[a-fA-F0-9]{32,64}\b', clean_text))),
        "domains": list(set(re.findall(domain_re, clean_text, re.IGNORECASE)))
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

    # Dynamically extract domains cited in reference/source/citation URLs
    dynamic_publishers: Set[str] = set()
    for ref_url in re.findall(
        r"(?:references?|sources?|see\s+also|read\s+more|link|url|via|courtesy|author|published\s+by|credit|report|research):\s*(https?://[^\s\)\],]+)",
        clean_text,
        re.IGNORECASE,
    ):
        m_host = re.match(r"https?://(?:www\.)?([^/:\s\)\],]+)", ref_url, re.IGNORECASE)
        if m_host:
            host = m_host.group(1).lower()
            dynamic_publishers.add(host)
            dynamic_publishers.add(_get_apex_domain(host))

    for m_host_match in re.finditer(
        r"https?://(?:www\.)?([^/:\s\)\],]+)(?:/[^\s\)\],]*(?:blog|research|threat-intel|advisory|advisories|security-center|posts?|articles?|news|publications?|topics/threat-intelligence)[^\s\)\],]*)",
        clean_text,
        re.IGNORECASE,
    ):
        host = m_host_match.group(1).lower()
        dynamic_publishers.add(host)
        dynamic_publishers.add(_get_apex_domain(host))

    for md_link in re.findall(
        r"\[(?:source|reference|report|link|article|read\s+more|blog)\]\((https?://[^\s\)]+)\)",
        clean_text,
        re.IGNORECASE,
    ):
        m_host = re.match(r"https?://(?:www\.)?([^/:\s\)]+)", md_link, re.IGNORECASE)
        if m_host:
            host = m_host.group(1).lower()
            dynamic_publishers.add(host)
            dynamic_publishers.add(_get_apex_domain(host))

    def _is_benign_or_publisher(d: str) -> bool:
        low = d.lower()
        if low.endswith(".local"):
            return True
        if low in _KNOWN_PUBLISHER_DOMAINS or low in dynamic_publishers:
            return True
        apex = _get_apex_domain(low)
        if apex in _KNOWN_PUBLISHER_DOMAINS or apex in dynamic_publishers:
            return True
        return False

    indicators["domains"] = [
        d.lower() for d in indicators["domains"]
        if not _is_benign_or_publisher(d)
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



def _format_rdap_date(date_str: str) -> str:
    """Format an RDAP ISO-8601 date string and compute age / NRD classification."""
    if not date_str:
        return "Unknown"
    try:
        clean = re.sub(r"Z$", "+00:00", str(date_str).strip())
        dt = datetime.fromisoformat(clean)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        days = (now - dt).days
        iso_day = date_str[:10]
        if days < 0:
            return iso_day
        if days < 60:
            return f"{iso_day} ({days} days old - RECENT/NRD)"
        elif days < 365:
            months = max(1, days // 30)
            return f"{iso_day} ({months} months old)"
        else:
            years = max(1, days // 365)
            return f"{iso_day} ({years} years old)"
    except Exception:
        return date_str[:10] if len(date_str) >= 10 else date_str


def query_rdap_domain(domain: str) -> str:
    """Query public RDAP service for domain registration age and registrar."""
    target_domain = _get_apex_domain(domain)
    url = f"https://rdap.org/domain/{target_domain}"
    headers = {"Accept": "application/rdap+json, application/json"}
    try:
        resp = httpx.get(url, headers=headers, follow_redirects=True, timeout=10.0)
        if resp.status_code == 200:
            data = resp.json()
            reg_date_raw = ""
            for ev in data.get("events", []):
                if ev.get("eventAction") in ("registration", "created"):
                    reg_date_raw = ev.get("eventDate", "")
                    break

            registrar = ""
            for ent in data.get("entities", []):
                roles = ent.get("roles", [])
                if "registrar" in roles:
                    vcard = ent.get("vcardArray")
                    if vcard and len(vcard) > 1 and isinstance(vcard[1], list):
                        for prop in vcard[1]:
                            if isinstance(prop, list) and len(prop) > 3 and prop[0] == "fn":
                                registrar = str(prop[3])
                                break
                    if not registrar and ent.get("handle"):
                        registrar = str(ent.get("handle"))
                    if registrar:
                        break

            parts = []
            if reg_date_raw:
                age_formatted = _format_rdap_date(reg_date_raw)
                parts.append(f"Registered: {age_formatted}")
            if registrar:
                parts.append(f"Registrar: {registrar}")

            if parts:
                return " | ".join(parts)
            return "Domain active (no creation date recorded in RDAP)."
        elif resp.status_code == 404:
            return "Domain not found on RDAP."
        return f"RDAP error: HTTP {resp.status_code}"
    except Exception as e:
        return f"Error querying RDAP: {e}"


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



def query_abuseipdb_ip(ip: str) -> str:
    """Query AbuseIPDB for IP abuse confidence score, reports, ISP, and usage type."""
    key = _setting("ABUSEIPDB_API_KEY")
    if not key:
        return "ABUSEIPDB_API_KEY not configured."
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": key,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": "90",
    }
    try:
        resp = httpx.get(url, headers=headers, params=params, timeout=10.0)
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            reports = data.get("totalReports", 0)
            isp = data.get("isp") or "Unknown"
            usage = data.get("usageType") or "Unknown"
            country = data.get("countryCode")

            parts = [f"Score: {score}% (Reports: {reports})", f"ISP: {isp}", f"Usage: {usage}"]
            if country:
                parts.append(f"Country: {country}")
            return " | ".join(parts)
        elif resp.status_code in (401, 403):
            return "AbuseIPDB Auth Error (check ABUSEIPDB_API_KEY)."
        elif resp.status_code == 429:
            return "AbuseIPDB rate limit exceeded."
        elif resp.status_code in (404, 422):
            return "No data on AbuseIPDB."
        return f"AbuseIPDB error: HTTP {resp.status_code}"
    except Exception as e:
        return f"Error querying AbuseIPDB: {e}"


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


def query_malwarebazaar(file_hash: str) -> str:
    """Query Abuse.ch MalwareBazaar for sample metadata, file type, signature, and YARA rules."""
    key = _setting("ABUSECH_API_KEY")
    if not key:
        return "ABUSECH_API_KEY not configured."
    url = "https://mb-api.abuse.ch/api/v1/"
    headers = {"Auth-Key": key}
    data = {"query": "get_info", "hash": file_hash}
    try:
        resp = httpx.post(url, headers=headers, data=data, timeout=10.0)
        if resp.status_code == 200:
            payload = resp.json()
            status = payload.get("query_status")
            if status == "ok" and payload.get("data"):
                item = payload["data"][0]
                sig = item.get("signature") or "Unknown"
                ftype = item.get("file_type") or "Unknown"
                delivery = item.get("delivery_method")
                raw_yara = item.get("yara_rules") or []
                yara_rules: List[str] = [
                    str(y.get("rule_name")) for y in raw_yara
                    if isinstance(y, dict) and y.get("rule_name")
                ]
                tags: List[str] = [str(t) for t in (item.get("tags") or []) if t]

                parts = [f"Family: {sig}", f"Type: {ftype}"]
                if delivery:
                    parts.append(f"Delivery: {delivery}")
                if yara_rules:
                    parts.append(f"YARA: {', '.join(yara_rules[:3])}")
                elif tags:
                    parts.append(f"Tags: {', '.join(tags[:3])}")
                return " | ".join(parts)
            elif status == "hash_not_found":
                return "No sample found on MalwareBazaar."
            else:
                return f"MalwareBazaar: {status}"
        elif resp.status_code in (401, 403):
            return "MalwareBazaar Auth Error (check ABUSECH_API_KEY)."
        return f"HTTP {resp.status_code}"
    except Exception as e:
        return f"Error querying MalwareBazaar: {e}"


def generate_enrichment_summary(threat_intel: str) -> str:
    """Extracts indicators and queries VT, returning a markdown summary."""
    indicators = extract_indicators(threat_intel)
    if not any(indicators.values()):
        return ""
        
    summary = ["\n\n### 🛡️ Automated Threat Enrichment (VT, GreyNoise, AbuseIPDB, Shodan, Censys, Abuse.ch, RDAP & MISP)"]
    
    from concurrent.futures import ThreadPoolExecutor
    
    def process_hash(h: str) -> str:
        res = query_vt_hash(h)
        mb_res = query_malwarebazaar(h)
        threatfox_res = query_threatfox(h)
        misp_res = query_misp_indicator(h)
        return (
            f"- **Hash {h}**:\n"
            f"  - *VirusTotal:* {res}\n"
            f"  - *Abuse.ch (MalwareBazaar):* {mb_res}\n"
            f"  - *Abuse.ch (ThreatFox):* {threatfox_res}\n"
            f"  - *Internal MISP:* {misp_res}"
        )

    def process_ip(ip: str) -> str:
        vt_res = query_vt_ip(ip)
        abuseipdb_res = query_abuseipdb_ip(ip)
        gn_res = query_greynoise_ip(ip)
        shodan_res = query_shodan_ip(ip)
        censys_res = query_censys_ip(ip)
        threatfox_res = query_threatfox(ip)
        misp_res = query_misp_indicator(ip)
        return (
            f"- **IP {ip}**:\n"
            f"  - *VirusTotal:* {vt_res}\n"
            f"  - *AbuseIPDB:* {abuseipdb_res}\n"
            f"  - *GreyNoise:* {gn_res}\n"
            f"  - *Shodan:* {shodan_res}\n"
            f"  - *Censys:* {censys_res}\n"
            f"  - *Abuse.ch (ThreatFox):* {threatfox_res}\n"
            f"  - *Internal MISP:* {misp_res}"
        )

    def process_domain(d: str) -> str:
        vt_res = query_vt_domain(d)
        rdap_res = query_rdap_domain(d)
        threatfox_res = query_threatfox(d)
        misp_res = query_misp_indicator(d)
        return (
            f"- **Domain {d}**:\n"
            f"  - *VirusTotal:* {vt_res}\n"
            f"  - *RDAP (Domain Age & Registrar):* {rdap_res}\n"
            f"  - *Abuse.ch (ThreatFox):* {threatfox_res}\n"
            f"  - *Internal MISP:* {misp_res}"
        )

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
