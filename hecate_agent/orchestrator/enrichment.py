import os
import re
import time
import httpx
import ipaddress
import logging
import urllib.parse
import uuid
import yaml
from datetime import datetime, timezone, date
from typing import List, Dict, Set, Tuple, Any, Optional, cast
from hecate_agent.core.sigma_semantics import semantic_problem


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
    "hybrid-analysis.com", "payload-security.com", "osv.dev", "api.osv.dev",
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
    """Extract IPs, Domains, Hashes, and CVEs from text using regex, refanging first."""
    if not text:
        return {"ips": [], "hashes": [], "domains": [], "cves": []}
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
        "domains": list(set(re.findall(domain_re, clean_text, re.IGNORECASE))),
        "cves": list(dict.fromkeys(cve.upper() for cve in re.findall(r'\b(?:CVE-\d{4}-\d{4,7}|GHSA-[2-9a-kmnp-z]{4}-[2-9a-kmnp-z]{4}-[2-9a-kmnp-z]{4})\b', clean_text, re.IGNORECASE))),
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

    raw_urls = re.findall(r'https?://[^\s<>"\'\)\]`]+', clean_text)
    filtered_urls = []
    for u in raw_urls:
        clean_u = u.rstrip(".,;:)")
        m_u_host = re.match(r"https?://(?:www\.)?([^/:\s\)\],]+)", clean_u, re.IGNORECASE)
        if m_u_host:
            u_host = m_u_host.group(1).lower()
            if _is_benign_or_publisher(u_host):
                continue
            if any(u_host.startswith(p) for p in ("127.", "10.", "192.168.", "172.", "0.0.0.0", "localhost")):
                continue
            filtered_urls.append(clean_u)

    indicators["urls"] = list(dict.fromkeys(filtered_urls))
    return indicators

def query_vt_hash(file_hash: str) -> str:
    api_key = _setting("VT_API_KEY")
    if not api_key:
        return "Not found or error."
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
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
            data = cast(Dict[str, Any], resp.json())
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
            data = cast(Dict[str, Any], resp.json())
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


_SPUR_CACHE: Dict[str, Tuple[float, str, Dict[str, Any]]] = {}
_SPUR_CACHE_TTL: float = 86400.0  # 24-hour cache TTL


def extract_spur_context(ip: str) -> Dict[str, Any]:
    """Query Spur.us Context API for structured IP intelligence, proxy detection, and tunnels."""
    clean_ip = refang(ip).strip()
    if not clean_ip:
        return {"configured": False, "error": "Empty IP address"}

    try:
        addr = ipaddress.ip_address(clean_ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved:
            return {"configured": True, "found": False, "message": "Private/internal IP address"}
    except ValueError:
        return {"configured": False, "error": f"Invalid IP address: {clean_ip}"}

    key = _setting("SPUR_API_KEY")
    if not key:
        return {"configured": False, "error": "SPUR_API_KEY not configured"}

    now = time.time()
    cached = _SPUR_CACHE.get(clean_ip)
    if cached and (now - cached[0] < _SPUR_CACHE_TTL):
        return cached[2]

    url = f"https://api.spur.us/v2/context/{clean_ip}"
    headers = {"Token": key, "Accept": "application/json"}
    try:
        resp = httpx.get(url, headers=headers, timeout=5.0)
        if resp.status_code == 200:
            data = cast(Dict[str, Any], resp.json())
            data["configured"] = True
            data["found"] = True
            return data
        elif resp.status_code == 404:
            return {"configured": True, "found": False, "message": "Not observed on Spur"}
        elif resp.status_code in (401, 403):
            return {"configured": True, "error": "Spur Auth Error (check SPUR_API_KEY)"}
        elif resp.status_code == 429:
            return {"configured": True, "error": "Spur rate limit exceeded"}
        return {"configured": True, "error": f"Spur API error: HTTP {resp.status_code}"}
    except httpx.TimeoutException:
        return {"configured": True, "error": "Spur query timed out"}
    except Exception as e:
        return {"configured": True, "error": f"Error querying Spur: {e}"}


def query_spur_ip(ip: str) -> str:
    """Query Spur.us Context API for residential proxies, VPN tunnels, and bulletproof infrastructure."""
    clean_ip = refang(ip).strip()
    if not clean_ip:
        return "Invalid IP address."

    try:
        addr = ipaddress.ip_address(clean_ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved:
            return "Private/internal IP address."
    except ValueError:
        return f"Invalid IP address: {clean_ip}"

    key = _setting("SPUR_API_KEY")
    if not key:
        return "SPUR_API_KEY not configured."

    now = time.time()
    cached = _SPUR_CACHE.get(clean_ip)
    if cached and (now - cached[0] < _SPUR_CACHE_TTL):
        return cached[1]

    data = extract_spur_context(clean_ip)
    if not data.get("configured", True):
        return str(data.get("error") or "SPUR_API_KEY not configured.")
    if data.get("error"):
        return str(data["error"])
    if not data.get("found", True):
        res = "Not observed on Spur."
        _SPUR_CACHE[clean_ip] = (now, res, data)
        return res

    infra = data.get("infrastructure") or ""
    as_info = data.get("as") or {}
    as_num = as_info.get("number")
    as_org = as_info.get("organization") or ""

    tunnels = data.get("tunnels") or []
    tunnel_strs = []
    for t in tunnels:
        if isinstance(t, dict):
            op = t.get("operator") or "Unknown"
            anon = " (Anonymous)" if t.get("anonymous") else ""
            tunnel_strs.append(f"{op}{anon}")
        elif isinstance(t, str):
            tunnel_strs.append(t)

    client = data.get("client") or {}
    proxies = client.get("proxies") or []
    risks = data.get("risks") or []
    location = data.get("location") or {}
    city = location.get("city")
    country = location.get("country")

    parts = []
    if infra:
        parts.append(f"Infra: {infra}")
    if as_num:
        parts.append(f"AS: AS{as_num} ({as_org})" if as_org else f"AS: AS{as_num}")
    elif as_org:
        parts.append(f"Org: {as_org}")
    if tunnel_strs:
        parts.append(f"Tunnels: {', '.join(tunnel_strs[:3])}")
    if proxies:
        parts.append(f"Proxies: {', '.join(str(p) for p in proxies[:3])}")
    if risks:
        parts.append(f"Risks: {', '.join(str(r) for r in risks[:4])}")
    loc_parts = [p for p in (city, country) if p]
    if loc_parts:
        parts.append(f"Loc: {', '.join(loc_parts)}")

    summary = " | ".join(parts) if parts else "No threat or proxy signals reported."
    _SPUR_CACHE[clean_ip] = (now, summary, data)
    return summary


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


_FEODO_CACHE: Dict[str, Any] = {"data": None, "ts": 0.0}
_SSLBL_CACHE: Dict[str, Any] = {"data": None, "ts": 0.0}


def _get_feodo_ip_map() -> Dict[str, Dict[str, Any]]:
    """Fetch and cache abuse.ch Feodo Tracker IP blocklist (1-hour TTL)."""
    now = time.time()
    if _FEODO_CACHE.get("data") is not None and (now - float(_FEODO_CACHE.get("ts", 0.0)) < 3600.0):
        return cast(Dict[str, Dict[str, Any]], _FEODO_CACHE["data"])
    try:
        url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
        resp = httpx.get(url, timeout=5.0)
        if resp.status_code == 200:
            entries = resp.json()
            ip_map: Dict[str, Dict[str, Any]] = {
                str(item["ip_address"]): item
                for item in entries
                if isinstance(item, dict) and item.get("ip_address")
            }
            _FEODO_CACHE["data"] = ip_map
            _FEODO_CACHE["ts"] = now
            return ip_map
    except Exception as e:
        logger.debug(f"Failed to fetch Feodo Tracker blocklist: {e}")
    cached = _FEODO_CACHE.get("data")
    return cast(Dict[str, Dict[str, Any]], cached) if cached is not None else {}


def _get_sslbl_fingerprint_map() -> Dict[str, Tuple[str, str]]:
    """Fetch and cache abuse.ch SSL Blacklist certificate & JA3 fingerprints (1-hour TTL)."""
    now = time.time()
    if _SSLBL_CACHE.get("data") is not None and (now - float(_SSLBL_CACHE.get("ts", 0.0)) < 3600.0):
        return cast(Dict[str, Tuple[str, str]], _SSLBL_CACHE["data"])
    try:
        url = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
        resp = httpx.get(url, timeout=5.0)
        if resp.status_code == 200:
            res_map: Dict[str, Tuple[str, str]] = {}
            for line in resp.text.splitlines():
                if not line or line.startswith("#"):
                    continue
                parts = line.split(",")
                if len(parts) >= 3:
                    dt, sha1, reason = parts[0].strip(), parts[1].strip().lower(), parts[2].strip()
                    res_map[sha1] = (reason, dt)
            try:
                ja3_resp = httpx.get("https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv", timeout=3.0)
                if ja3_resp.status_code == 200:
                    for line in ja3_resp.text.splitlines():
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split(",")
                        if len(parts) >= 4:
                            ja3_md5, reason = parts[0].strip().lower(), parts[3].strip()
                            res_map[ja3_md5] = (f"JA3 {reason}", parts[1].strip())
            except Exception:
                pass
            _SSLBL_CACHE["data"] = res_map
            _SSLBL_CACHE["ts"] = now
            return res_map
    except Exception as e:
        logger.debug(f"Failed to fetch SSLBL blocklist: {e}")
    cached = _SSLBL_CACHE.get("data")
    return cast(Dict[str, Tuple[str, str]], cached) if cached is not None else {}


def query_feodotracker_ip(ip: str) -> str:
    """Check if an IPv4 address is an active botnet C2 on abuse.ch Feodo Tracker."""
    clean_ip = ip.strip()
    feodo_map = _get_feodo_ip_map()
    if not feodo_map:
        return "Not listed on Feodo Tracker (feed empty/clean)."
    entry = feodo_map.get(clean_ip)
    if entry:
        malware = entry.get("malware") or "Unknown Botnet"
        status = entry.get("status") or "active"
        port = entry.get("port")
        asn = entry.get("as_name") or ""
        first_seen = entry.get("first_seen", "").split()[0]
        details = [f"Botnet C2: {malware}"]
        if port:
            details.append(f"Port: {port}")
        details.append(f"Status: {status}")
        if first_seen:
            details.append(f"First Seen: {first_seen}")
        if asn:
            details.append(f"ASN: {asn}")
        return " · ".join(details)
    return "Not listed on Feodo Tracker (clean)."


def query_sslbl_fingerprint(fingerprint: str) -> str:
    """Check if a SHA1 SSL certificate or JA3 MD5 hash is on abuse.ch SSL Blacklist."""
    clean_fp = fingerprint.strip().lower()
    sslbl_map = _get_sslbl_fingerprint_map()
    if not sslbl_map:
        return "Not listed on SSLBL (feed empty/clean)."
    entry = sslbl_map.get(clean_fp)
    if entry:
        reason, listing_date = entry
        date_str = f" · Listed: {listing_date.split()[0]}" if listing_date else ""
        return f"Malicious SSL Cert / JA3: {reason}{date_str}"
    return "Not listed on SSLBL (clean)."


_TOR_EXIT_CACHE: Dict[str, Any] = {"data": set(), "ts": 0.0}
_TOR_EXIT_TTL: float = 3600.0  # 1-hour cache TTL (matches Tor consensus cycle)


def _get_tor_exit_nodes() -> Set[str]:
    """Fetch and cache the official Tor Project bulk exit node list (1-hour TTL)."""
    now = time.time()
    cached_set = _TOR_EXIT_CACHE.get("data")
    if cached_set and (now - float(_TOR_EXIT_CACHE.get("ts", 0.0)) < _TOR_EXIT_TTL):
        return cast(Set[str], cached_set)
    try:
        url = "https://check.torproject.org/torbulkexitlist"
        resp = httpx.get(url, timeout=5.0)
        if resp.status_code == 200:
            exit_ips: Set[str] = {
                line.strip()
                for line in resp.text.splitlines()
                if line.strip() and not line.startswith("#")
            }
            if exit_ips:
                _TOR_EXIT_CACHE["data"] = exit_ips
                _TOR_EXIT_CACHE["ts"] = now
                return exit_ips
    except Exception as e:
        logger.debug(f"Failed to fetch Tor bulk exit list: {e}")
    return cast(Set[str], cached_set) if cached_set else set()


def is_tor_exit_node(ip: str) -> bool:
    """Return True if the IP address is an active Tor Project exit node."""
    clean_ip = refang(ip).strip()
    if not clean_ip:
        return False
    return clean_ip in _get_tor_exit_nodes()


def query_tor_exit(ip: str) -> str:
    """Query whether an IP is an active Tor exit node."""
    clean_ip = refang(ip).strip()
    if not clean_ip:
        return "Invalid IP address."
    if is_tor_exit_node(clean_ip):
        return "Tor Exit Node: Confirmed Active Exit Node [Tor Project consensus]"
    return "Not a Tor exit node."


_IPINFO_CACHE: Dict[str, Tuple[float, str, Dict[str, Any]]] = {}
_IPINFO_CACHE_TTL: float = 86400.0  # 24-hour cache TTL


def extract_ipinfo_context(ip: str) -> Dict[str, Any]:
    """Query IPinfo.io for IP geolocation, organization, hosting/datacenter classification, and privacy."""
    clean_ip = refang(ip).strip()
    if not clean_ip:
        return {"configured": False, "error": "Empty IP address"}

    try:
        addr = ipaddress.ip_address(clean_ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return {"configured": True, "found": False, "bogon": True, "message": "Private/internal IP address."}
    except ValueError:
        return {"configured": False, "error": f"Invalid IP address: {clean_ip}"}

    now = time.time()
    cached = _IPINFO_CACHE.get(clean_ip)
    if cached and (now - cached[0] < _IPINFO_CACHE_TTL):
        return cached[2]

    token = _setting("IPINFO_TOKEN") or _setting("IPINFO_API_KEY")
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    url = f"https://ipinfo.io/{clean_ip}/json"
    try:
        resp = httpx.get(url, headers=headers, timeout=5.0)
        if resp.status_code == 200:
            data = cast(Dict[str, Any], resp.json())
            data["configured"] = True
            data["found"] = True
            return data
        elif resp.status_code == 404:
            return {"configured": True, "found": False, "message": "Not found on IPinfo"}
        elif resp.status_code == 429:
            return {"configured": True, "error": "IPinfo rate limit exceeded"}
        return {"configured": True, "error": f"IPinfo HTTP {resp.status_code}"}
    except Exception as e:
        return {"configured": True, "error": f"Error querying IPinfo: {e}"}


def query_ipinfo_ip(ip: str) -> str:
    """Query IPinfo for ASN, organization, hosting type, and privacy flags."""
    clean_ip = refang(ip).strip()
    if not clean_ip:
        return "Invalid IP address."

    data = extract_ipinfo_context(clean_ip)
    if not data.get("configured", True):
        return str(data.get("error") or "IPinfo error.")
    if data.get("error"):
        return str(data["error"])
    if not data.get("found", True):
        return str(data.get("message") or "Not found on IPinfo.")

    now = time.time()
    cached = _IPINFO_CACHE.get(clean_ip)
    if cached and (now - cached[0] < _IPINFO_CACHE_TTL):
        return cached[1]

    org = data.get("org") or ""
    hostname = data.get("hostname") or ""
    city = data.get("city")
    region = data.get("region")
    country = data.get("country")
    anycast = data.get("anycast", False)
    privacy = data.get("privacy") or {}
    company = data.get("company") or {}

    is_vpn = privacy.get("vpn", False)
    is_proxy = privacy.get("proxy", False)
    is_tor = privacy.get("tor", False)
    is_hosting = privacy.get("hosting", False) or company.get("type") == "hosting"
    service = privacy.get("service")

    tags = []
    if is_tor:
        tags.append("Tor")
    if is_vpn:
        tags.append(f"VPN ({service})" if service else "VPN")
    if is_proxy:
        tags.append("Proxy")
    if is_hosting:
        tags.append("Hosting/Datacenter")
    if anycast:
        tags.append("Anycast")

    parts = []
    if tags:
        parts.append(f"Classification: {', '.join(tags)}")
    elif is_hosting:
        parts.append("Classification: Hosting/Datacenter")

    if org:
        parts.append(f"Org: {org}")
    if hostname and not hostname.endswith(".in-addr.arpa"):
        parts.append(f"Host: {hostname}")

    loc_parts = [p for p in (city, region, country) if p]
    if loc_parts:
        parts.append(f"Loc: {', '.join(loc_parts)}")

    summary = " | ".join(parts) if parts else "Benign ISP / Non-proxy."
    _IPINFO_CACHE[clean_ip] = (now, summary, data)
    return summary


def query_anonymity_proxy_ip(ip: str) -> str:
    """Unified anonymity & proxy intelligence combining Tor Project consensus + IPinfo context."""
    clean_ip = refang(ip).strip()
    if not clean_ip:
        return "Invalid IP address."

    try:
        addr = ipaddress.ip_address(clean_ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return "Private/internal IP address."
    except ValueError:
        return f"Invalid IP address: {clean_ip}"

    tor_active = is_tor_exit_node(clean_ip)
    ipinfo_str = query_ipinfo_ip(clean_ip)

    items = []
    sources = set()
    if tor_active:
        items.append("Tor Exit Node (Active)")
        sources.add("Tor Project")

    if ipinfo_str and not ipinfo_str.startswith("Error") and not ipinfo_str.startswith("IPinfo HTTP") and not ipinfo_str.startswith("Private"):
        items.append(ipinfo_str)
        sources.add("IPinfo")

    if not items:
        if tor_active:
            return "Tor Exit Node: Active [Tor Project]"
        return "Benign ISP / Non-proxy."

    src_tag = f" [{', '.join(sorted(sources))}]" if sources else ""
    return f"{' | '.join(items)}{src_tag}"


def query_urlhaus_url(url: str) -> str:
    """Query abuse.ch URLhaus API for malicious URL status, threat classification, and payload info."""
    key = _setting("ABUSECH_API_KEY")
    if not key:
        return "ABUSECH_API_KEY not configured."
    clean_url = url.strip()
    api_url = "https://urlhaus-api.abuse.ch/v1/url/"
    headers = {"Auth-Key": key}
    data = {"url": clean_url}
    try:
        resp = httpx.post(api_url, headers=headers, data=data, timeout=8.0)
        if resp.status_code == 200:
            res_json = resp.json()
            q_status = res_json.get("query_status")
            if q_status == "ok":
                url_status = res_json.get("url_status") or "unknown"
                threat = res_json.get("threat") or "malware_download"
                tags = res_json.get("tags") or []
                payloads = res_json.get("payloads") or []
                sig = ""
                if payloads and isinstance(payloads, list):
                    p0 = payloads[0]
                    if isinstance(p0, dict):
                        sig = p0.get("signature") or p0.get("file_type") or ""
                parts = [f"Status: {url_status}", f"Threat: {threat}"]
                if sig:
                    parts.append(f"Payload: {sig}")
                if tags:
                    parts.append(f"Tags: {', '.join(str(t) for t in tags[:3])}")
                return " | ".join(parts)
            elif q_status == "no_results":
                return "Not listed on URLhaus."
            return f"URLhaus: {q_status}"
        elif resp.status_code in (401, 403):
            return "URLhaus Auth Error (check ABUSECH_API_KEY)."
        return f"HTTP {resp.status_code}"
    except Exception as e:
        return f"Error querying URLhaus: {e}"


def query_urlhaus_host(host: str) -> str:
    """Query abuse.ch URLhaus API for host (domain or IP) malware distribution history."""
    key = _setting("ABUSECH_API_KEY")
    if not key:
        return "ABUSECH_API_KEY not configured."
    clean_host = host.strip().lower()
    api_url = "https://urlhaus-api.abuse.ch/v1/host/"
    headers = {"Auth-Key": key}
    data = {"host": clean_host}
    try:
        resp = httpx.post(api_url, headers=headers, data=data, timeout=8.0)
        if resp.status_code == 200:
            res_json = resp.json()
            q_status = res_json.get("query_status")
            if q_status == "ok":
                cnt = res_json.get("url_count")
                if cnt is None:
                    cnt = len(res_json.get("urls") or [])
                firstseen = str(res_json.get("firstseen") or "")[:10]
                parts = [f"Malware host ({cnt} URL(s))"]
                if firstseen:
                    parts.append(f"First seen: {firstseen}")
                return " | ".join(parts)
            elif q_status == "no_results":
                return "Not listed on URLhaus."
            return f"URLhaus: {q_status}"
        elif resp.status_code in (401, 403):
            return "URLhaus Auth Error (check ABUSECH_API_KEY)."
        return f"HTTP {resp.status_code}"
    except Exception as e:
        return f"Error querying URLhaus: {e}"


def query_urlhaus_payload(file_hash: str) -> str:
    """Query abuse.ch URLhaus API for payload hash (MD5 or SHA256) distribution info."""
    key = _setting("ABUSECH_API_KEY")
    if not key:
        return "ABUSECH_API_KEY not configured."
    clean_hash = file_hash.strip().lower()
    api_url = "https://urlhaus-api.abuse.ch/v1/payload/"
    headers = {"Auth-Key": key}
    field = "sha256_hash" if len(clean_hash) == 64 else "md5_hash"
    data = {field: clean_hash}
    try:
        resp = httpx.post(api_url, headers=headers, data=data, timeout=8.0)
        if resp.status_code == 200:
            res_json = resp.json()
            q_status = res_json.get("query_status")
            if q_status == "ok":
                sig = res_json.get("signature") or "Unknown"
                ftype = res_json.get("file_type") or "Unknown"
                cnt = res_json.get("url_count") or 0
                return f"Payload: {sig} ({ftype}) | Seen on {cnt} URL(s)"
            elif q_status == "no_results":
                return "No payload on URLhaus."
            return f"URLhaus: {q_status}"
        elif resp.status_code in (401, 403):
            return "URLhaus Auth Error (check ABUSECH_API_KEY)."
        return f"HTTP {resp.status_code}"
    except Exception as e:
        return f"Error querying URLhaus: {e}"


_URLSCAN_CACHE: Dict[str, Tuple[float, str]] = {}
_URLSCAN_CACHE_TTL: float = 86400.0  # 24-hour cache TTL


def extract_web_lure_payloads(text: str) -> List[Dict[str, str]]:
    """Inspect HTML/DOM/script contents to detect ClickFix, fake CAPTCHA, and clipboard injection lures."""
    results: List[Dict[str, str]] = []
    if not text:
        return results

    # 1. Direct clipboard writing literals: navigator.clipboard.writeText("...")
    direct_matches = re.finditer(
        r"""navigator\.clipboard\.writeText\(\s*(["'`])((?:\\.|(?!\1).)*)\1\s*\)""",
        text,
        re.IGNORECASE | re.DOTALL,
    )
    for dm in direct_matches:
        raw = dm.group(2).replace(r'\"', '"').replace(r"\'", "'").strip()
        if raw and len(raw) >= 4:
            results.append({"command": raw, "source": "clipboard_writeText", "lure": "direct_clipboard_injection"})

    # 2. Variable-based clipboard writing: const cmd = "..."; navigator.clipboard.writeText(cmd);
    var_matches = re.finditer(
        r"""navigator\.clipboard\.writeText\(\s*([a-zA-Z0-9_$]+)\s*\)""",
        text,
        re.IGNORECASE,
    )
    for vm in var_matches:
        var_name = vm.group(1)
        if var_name.lower() not in {"data", "event", "e"}:
            var_def = re.search(
                rf"""(?:const|let|var)\s+{re.escape(var_name)}\s*=\s*(["'`])((?:\\.|(?!\1).)*)\1""",
                text,
                re.IGNORECASE | re.DOTALL,
            )
            if var_def:
                raw = var_def.group(2).replace(r'\"', '"').replace(r"\'", "'").strip()
                if raw and len(raw) >= 4 and not any(r["command"] == raw for r in results):
                    results.append({"command": raw, "source": f"clipboard_var({var_name})", "lure": "variable_clipboard_injection"})

    # 3. Fake CAPTCHA / Human verification prompt
    has_captcha_prompt = bool(
        re.search(
            r"""(verify\s+you\s+are\s+human|cloudflare\s+human\s+verification|robot\s+check|press\s+(?:win(?:dows)?(?:\s*key)?\s*\+\s*r|ctrl\s*\+\s*v|cmd\s*\+\s*v|terminal))""",
            text,
            re.IGNORECASE,
        )
    )

    # 4. Known command execution patterns in scripts
    cmd_patterns = [
        ("powershell", re.compile(r"""(?:powershell(?:\.exe)?|pwsh)\s+(?:-[a-zA-Z0-9_\-]+\s+)*(?:-[eE](?:nc(?:odedcommand)?)?|iex|invoke-expression)\s+["'`]?([^"'`\n;]+)""", re.IGNORECASE)),
        ("bash", re.compile(r"""(?:curl|wget)\s+-[sSfLkA-Za-z0-9\-_./:=?&]+\s+https?://[^\s;&"'`]+(?:\s*\|\s*(?:ba)?sh\b)?""", re.IGNORECASE)),
        ("mshta", re.compile(r"""mshta(?:\.exe)?\s+https?://[^\s;&"'`]+""", re.IGNORECASE)),
        ("osascript", re.compile(r"""osascript\s+-e\s+["']([^"']+)["']""", re.IGNORECASE)),
    ]
    for ctype, pat in cmd_patterns:
        for match in pat.finditer(text):
            cmd = match.group(0).strip().rstrip("\\")
            if len(cmd) >= 8 and not any(r["command"] == cmd for r in results):
                results.append({
                    "command": cmd,
                    "source": ctype,
                    "lure": "fake_captcha_lure" if has_captcha_prompt else "embedded_script",
                })

    return results


def query_urlscan_url(url: str, check_lures: bool = True) -> str:
    """Query URLScan.io API for recent scan verdicts, hosted infrastructure, redirect chains, and DOM lure scripts."""
    clean_url = url.strip()
    now = time.monotonic()
    cached = _URLSCAN_CACHE.get(f"url:{clean_url}")
    if cached and (now - cached[0] < _URLSCAN_CACHE_TTL):
        return cached[1]

    api_url = "https://urlscan.io/api/v1/search/"
    headers = {"Accept": "application/json"}
    key = _setting("URLSCAN_API_KEY")
    if key:
        headers["API-Key"] = key

    query = f'page.url.keyword:"{clean_url}" OR page.url:"{clean_url}"'
    params: Dict[str, str | int] = {"q": query, "size": 1}

    try:
        resp = httpx.get(api_url, headers=headers, params=params, timeout=8.0)
        if resp.status_code == 200:
            data = resp.json()
            results = data.get("results", [])
            if not results:
                res = "Not indexed on URLScan.io."
                _URLSCAN_CACHE[f"url:{clean_url}"] = (now, res)
                return res

            r0 = results[0]
            verdicts = r0.get("verdicts", {})
            overall = verdicts.get("overall", {})
            malicious = overall.get("malicious", False)
            score = overall.get("score", 0)
            categories = overall.get("categories", [])
            brands = overall.get("brands", [])
            tags = overall.get("tags", [])

            page = r0.get("page", {})
            p_ip = page.get("ip", "unknown")
            p_asn = page.get("asn", "")
            p_asnname = page.get("asnname", "")
            p_country = page.get("country", "")
            p_title = page.get("title", "")

            result_url = r0.get("result", "")

            status_str = f"Malicious (Score: {score}/100)" if malicious else f"Benign/Neutral (Score: {score}/100)"
            parts = [f"Status: {status_str}"]

            if tags:
                parts.append(f"Tags: {', '.join(str(t) for t in tags[:3])}")
            if brands:
                parts.append(f"Target Brand: {', '.join(str(b) for b in brands[:3])}")

            host_parts = [p_ip]
            if p_asn:
                host_parts.append(f"{p_asn} {p_asnname}".strip())
            if p_country:
                host_parts.append(p_country)
            parts.append(f"Host: {' | '.join(host_parts)}")

            if p_title:
                parts.append(f"Title: {p_title[:45]}")

            if check_lures:
                text_corpus = f"{p_title} {' '.join(str(t) for t in tags)} {' '.join(str(c) for c in categories)}"
                lures = extract_web_lure_payloads(text_corpus)
                if lures:
                    parts.append(f"Lure: {lures[0]['command'][:60]}")

            if result_url:
                parts.append(f"Scan: {result_url}")

            res = " | ".join(parts)
            _URLSCAN_CACHE[f"url:{clean_url}"] = (now, res)
            return res
        elif resp.status_code == 429:
            return "URLScan.io rate limit exceeded."
        elif resp.status_code in (401, 403):
            return "URLScan.io Auth Error (check URLSCAN_API_KEY)."
        return f"HTTP {resp.status_code}"
    except Exception as e:
        return f"Error querying URLScan.io: {e}"


def query_urlscan_domain(domain: str) -> str:
    """Query URLScan.io API for recent domain scan verdicts, lure activity, and IP/ASN hosting info."""
    clean_domain = domain.strip().lower()
    now = time.monotonic()
    cached = _URLSCAN_CACHE.get(f"domain:{clean_domain}")
    if cached and (now - cached[0] < _URLSCAN_CACHE_TTL):
        return cached[1]

    api_url = "https://urlscan.io/api/v1/search/"
    headers = {"Accept": "application/json"}
    key = _setting("URLSCAN_API_KEY")
    if key:
        headers["API-Key"] = key

    query = f'page.domain:"{clean_domain}"'
    params: Dict[str, str | int] = {"q": query, "size": 1}

    try:
        resp = httpx.get(api_url, headers=headers, params=params, timeout=8.0)
        if resp.status_code == 200:
            data = resp.json()
            results = data.get("results", [])
            if not results:
                res = "Not indexed on URLScan.io."
                _URLSCAN_CACHE[f"domain:{clean_domain}"] = (now, res)
                return res

            r0 = results[0]
            verdicts = r0.get("verdicts", {})
            overall = verdicts.get("overall", {})
            malicious = overall.get("malicious", False)
            score = overall.get("score", 0)
            brands = overall.get("brands", [])
            tags = overall.get("tags", [])

            page = r0.get("page", {})
            p_ip = page.get("ip", "unknown")
            p_asn = page.get("asn", "")
            p_asnname = page.get("asnname", "")
            p_country = page.get("country", "")
            p_title = page.get("title", "")

            result_url = r0.get("result", "")

            status_str = f"Malicious (Score: {score}/100)" if malicious else f"Benign/Neutral (Score: {score}/100)"
            parts = [f"Status: {status_str}"]

            if tags:
                parts.append(f"Tags: {', '.join(str(t) for t in tags[:3])}")
            if brands:
                parts.append(f"Target Brand: {', '.join(str(b) for b in brands[:3])}")

            host_parts = [p_ip]
            if p_asn:
                host_parts.append(f"{p_asn} {p_asnname}".strip())
            if p_country:
                host_parts.append(p_country)
            parts.append(f"Host: {' | '.join(host_parts)}")

            if p_title:
                parts.append(f"Title: {p_title[:45]}")

            if result_url:
                parts.append(f"Scan: {result_url}")

            res = " | ".join(parts)
            _URLSCAN_CACHE[f"domain:{clean_domain}"] = (now, res)
            return res
        elif resp.status_code == 429:
            return "URLScan.io rate limit exceeded."
        elif resp.status_code in (401, 403):
            return "URLScan.io Auth Error (check URLSCAN_API_KEY)."
        return f"HTTP {resp.status_code}"
    except Exception as e:
        return f"Error querying URLScan.io: {e}"


def submit_urlscan_detonation(
    url: str,
    visibility: str = "unlisted",
    poll: bool = False,
    max_wait_seconds: float = 30.0,
) -> Dict[str, Any]:
    """Submit a suspicious URL for live browser detonation on URLScan.io.

    Returns the submission record or polls for full DOM and network telemetry if poll=True.
    """
    clean_url = url.strip()
    key = _setting("URLSCAN_API_KEY")
    if not key:
        return {
            "status": "error",
            "message": "URLScan API key required for live detonation (set URLSCAN_API_KEY).",
        }

    api_url = "https://urlscan.io/api/v1/scan/"
    headers = {"API-Key": key, "Content-Type": "application/json"}
    payload = {"url": clean_url, "visibility": visibility}

    try:
        resp = httpx.post(api_url, headers=headers, json=payload, timeout=15.0)
        if resp.status_code in (200, 201):
            data = resp.json()
            scan_uuid = data.get("uuid")
            if poll and scan_uuid:
                return poll_urlscan_result(scan_uuid, max_wait_seconds=max_wait_seconds)
            return {
                "status": "submitted",
                "uuid": scan_uuid,
                "result": data.get("result", ""),
                "api": data.get("api", ""),
                "message": data.get("message", "Submission successful"),
            }
        elif resp.status_code == 429:
            return {"status": "rate_limited", "message": "URLScan.io rate limit exceeded."}
        elif resp.status_code in (400, 401, 403):
            return {"status": "error", "message": f"URLScan.io HTTP {resp.status_code}: {resp.text}"}
        return {"status": "error", "message": f"URLScan.io returned HTTP {resp.status_code}"}
    except Exception as e:
        return {"status": "error", "message": f"Error submitting to URLScan.io: {e}"}


def poll_urlscan_result(
    uuid_str: str,
    max_wait_seconds: float = 30.0,
    poll_interval: float = 2.0,
) -> Dict[str, Any]:
    """Poll URLScan.io result endpoint until scan completes or timeout expires."""
    clean_uuid = uuid_str.strip()
    if "urlscan.io" in clean_uuid:
        m = re.search(r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", clean_uuid, re.IGNORECASE)
        if m:
            clean_uuid = m.group(1)
        else:
            clean_uuid = clean_uuid.rstrip("/").split("/")[-1]

    api_url = f"https://urlscan.io/api/v1/result/{clean_uuid}/"
    headers = {"Accept": "application/json"}
    key = _setting("URLSCAN_API_KEY")
    if key:
        headers["API-Key"] = key

    start_time = time.monotonic()
    while time.monotonic() - start_time < max_wait_seconds:
        try:
            resp = httpx.get(api_url, headers=headers, timeout=10.0)
            if resp.status_code == 200:
                data = cast(Dict[str, Any], resp.json())
                data["status"] = "ready"
                return data
            elif resp.status_code == 404:
                # Detonation still in execution
                time.sleep(poll_interval)
                continue
            elif resp.status_code == 429:
                return {"status": "rate_limited", "uuid": clean_uuid, "message": "URLScan.io rate limit exceeded."}
            else:
                return {"status": "error", "uuid": clean_uuid, "message": f"HTTP {resp.status_code}"}
        except Exception:
            time.sleep(poll_interval)

    return {"status": "pending", "uuid": clean_uuid, "message": f"Scan pending or timed out after {max_wait_seconds}s"}


def extract_http_transactions(scan_result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Parse data.requests from URLScan result to extract network transactions and payload downloads."""
    data = scan_result.get("data", {})
    raw_requests = data.get("requests") if isinstance(data, dict) else None
    if not isinstance(raw_requests, list):
        raw_requests = scan_result.get("requests", [])
    if not isinstance(raw_requests, list):
        return []

    transactions: List[Dict[str, Any]] = []
    payload_extensions = (
        ".exe", ".dll", ".dmg", ".pkg", ".iso", ".zip", ".rar", ".7z",
        ".tar.gz", ".ps1", ".bat", ".cmd", ".sh", ".vbs", ".js", ".msi",
        ".scr", ".bin", ".app", ".apk",
    )
    payload_mime_types = (
        "application/octet-stream",
        "application/x-msdownload",
        "application/x-apple-diskimage",
        "application/zip",
        "application/x-rar",
        "application/x-7z-compressed",
        "application/x-sh",
        "application/x-powershell",
        "text/x-shellscript",
        "text/x-python",
    )

    for item in raw_requests:
        if not isinstance(item, dict):
            continue

        req_obj = item.get("request", {})
        if isinstance(req_obj, dict) and "request" in req_obj and isinstance(req_obj["request"], dict):
            req_info = req_obj.get("request", {})
        elif isinstance(req_obj, dict):
            req_info = req_obj
        else:
            req_info = {}

        resp_obj = item.get("response", {})
        if isinstance(resp_obj, dict) and "response" in resp_obj and isinstance(resp_obj["response"], dict):
            resp_info = resp_obj.get("response", {})
        elif isinstance(resp_obj, dict):
            resp_info = resp_obj
        else:
            resp_info = {}

        req_url = req_info.get("url") or item.get("url", "")
        if not req_url or not isinstance(req_url, str):
            continue

        method = str(req_info.get("method") or "GET").upper()
        req_headers = req_info.get("headers") or {}
        resp_headers = resp_info.get("headers") or {}
        status = resp_info.get("status")
        mime_type = str(
            resp_info.get("mimeType")
            or resp_headers.get("content-type")
            or resp_headers.get("Content-Type")
            or ""
        )
        remote_ip = str(resp_info.get("remoteIPAddress") or item.get("ip") or "").strip()
        remote_port = resp_info.get("remotePort")

        parsed = urllib.parse.urlsplit(req_url)
        host = (parsed.hostname or "").lower()
        path = parsed.path or ""

        if not remote_port:
            remote_port = 443 if parsed.scheme == "https" else 80

        is_payload = False
        lower_path = path.lower()
        if any(lower_path.endswith(ext) for ext in payload_extensions):
            is_payload = True
        elif any(pm in mime_type.lower() for pm in payload_mime_types):
            is_payload = True

        transactions.append({
            "url": req_url,
            "method": method,
            "host": host,
            "path": path,
            "status": status,
            "mime_type": mime_type,
            "remote_ip": remote_ip,
            "remote_port": int(remote_port) if remote_port else 80,
            "headers": {"request": req_headers, "response": resp_headers},
            "is_payload": is_payload,
        })

    return transactions


def generate_transaction_sigma_rules(
    transactions: List[Dict[str, Any]],
    hunt_id: Optional[str] = None,
    title_prefix: str = "Suspicious Web Lure Detonation",
) -> List[Dict[str, Any]]:
    """Generate validated Sigma rules for 'proxy' and 'network_connection' log sources from HTTP transactions."""
    if not transactions:
        return []

    rules: List[Dict[str, Any]] = []

    # Priority to payload transactions if observed, else fallback to all
    payload_txs = [tx for tx in transactions if tx.get("is_payload")]
    target_txs = payload_txs if payload_txs else transactions

    # 1. Web Proxy Rule
    hosts = sorted({tx["host"] for tx in target_txs if tx.get("host")})
    paths = sorted({tx["path"] for tx in target_txs if tx.get("path") and tx["path"] != "/"})

    if hosts or paths:
        proxy_selection: Dict[str, Any] = {}
        if hosts:
            proxy_selection["cs-host"] = hosts if len(hosts) > 1 else hosts[0]
        if paths:
            payload_exts = sorted({
                f".{p.split('.')[-1].lower()}"
                for p in paths
                if "." in p and p.split(".")[-1].lower() in (
                    "exe", "dll", "dmg", "pkg", "zip", "iso", "ps1", "sh", "bat", "vbs", "js"
                )
            })
            if payload_exts:
                proxy_selection["c-uri-stem|endswith"] = payload_exts if len(payload_exts) > 1 else payload_exts[0]
            else:
                proxy_selection["c-uri-stem"] = paths if len(paths) > 1 else paths[0]

        proxy_desc = "Detects web proxy requests to adversary staging domains, lure paths, or weaponized payload downloads captured during live detonation."
        proxy_problem = semantic_problem({"selection": proxy_selection, "condition": "selection"}, "proxy", proxy_desc)
        if not proxy_problem:
            proxy_doc: Dict[str, Any] = {
                "title": f"{title_prefix} - Web Proxy Staging and Payload Delivery",
                "id": str(uuid.uuid4()),
                "status": "experimental",
                "description": proxy_desc,
                "references": ["https://urlscan.io"],
                "author": "hecate (auto-generated from urlscan detonation)",
                "date": date.today().isoformat(),
                "tags": ["attack.initial_access", "attack.t1189", "attack.t1204"],
                "logsource": {"category": "proxy"},
                "detection": {
                    "selection": proxy_selection,
                    "condition": "selection",
                },
                "falsepositives": ["Legitimate downloads from CDN or multi-tenant hosting with identical naming conventions"],
                "level": "high",
            }
            if hunt_id:
                proxy_doc["hunt_id"] = hunt_id
            proxy_doc["rule_yaml"] = yaml.safe_dump(proxy_doc, sort_keys=False, allow_unicode=True, width=100)
            rules.append(proxy_doc)

    # 2. Network Connection Rule
    ips = sorted({
        tx["remote_ip"] for tx in target_txs
        if tx.get("remote_ip") and not tx["remote_ip"].startswith(("127.", "10.", "192.168.", "172.16.", "0.0.0.0"))
    })
    ports = sorted({tx["remote_port"] for tx in target_txs if tx.get("remote_port")})

    if ips:
        net_selection: Dict[str, Any] = {"DestinationIp": ips if len(ips) > 1 else ips[0]}
        if ports and ports != [80] and ports != [443] and ports != [80, 443]:
            net_selection["DestinationPort"] = ports if len(ports) > 1 else ports[0]

        net_desc = "Detects network connections to remote IP addresses associated with malicious web lures and staging infrastructure."
        net_problem = semantic_problem({"selection": net_selection, "condition": "selection"}, "network_connection", net_desc)
        if not net_problem:
            net_doc: Dict[str, Any] = {
                "title": f"{title_prefix} - Outbound Connection to Lure Infrastructure",
                "id": str(uuid.uuid4()),
                "status": "experimental",
                "description": net_desc,
                "references": ["https://urlscan.io"],
                "author": "hecate (auto-generated from urlscan detonation)",
                "date": date.today().isoformat(),
                "tags": ["attack.command_and_control", "attack.t1105"],
                "logsource": {"category": "network_connection"},
                "detection": {
                    "selection": net_selection,
                    "condition": "selection",
                },
                "falsepositives": ["Shared cloud or reverse proxy IP addresses serving multiple distinct organizations"],
                "level": "high",
            }
            if hunt_id:
                net_doc["hunt_id"] = hunt_id
            net_doc["rule_yaml"] = yaml.safe_dump(net_doc, sort_keys=False, allow_unicode=True, width=100)
            rules.append(net_doc)

    return rules


_CRTSH_CACHE: Dict[str, Tuple[float, str, List[str]]] = {}
_CRTSH_CACHE_TTL: float = 86400.0  # 24-hour cache TTL

_SHARED_HOSTING_SUFFIXES: Set[str] = {
    "pages.dev", "github.io", "gitlab.io", "workers.dev", "herokuapp.com",
    "azurewebsites.net", "s3.amazonaws.com", "cloudfront.net", "ngrok-free.app",
    "trycloudflare.com", "duckdns.org", "no-ip.com", "ddns.net", "firebaseapp.com",
}


def extract_sibling_domains_from_crtsh(domain: str) -> List[str]:
    """Query crt.sh Certificate Transparency logs to discover co-issued sibling subdomains and staging infrastructure."""
    clean = domain.strip().lower()
    now = time.monotonic()
    cached = _CRTSH_CACHE.get(clean)
    if cached and (now - cached[0] < _CRTSH_CACHE_TTL):
        return cached[2]

    apex = _get_apex_domain(clean)
    if any(clean.endswith(f".{suffix}") or clean == suffix for suffix in _SHARED_HOSTING_SUFFIXES):
        query_param = clean
    elif any(apex.endswith(f".{suffix}") or apex == suffix for suffix in _SHARED_HOSTING_SUFFIXES):
        query_param = clean
    else:
        query_param = f"%.{apex}" if apex else clean

    url = "https://crt.sh/"
    headers = {"Accept": "application/json", "User-Agent": "Hecate-Agent/2.0 (Threat-Hunting)"}
    params = {"q": query_param, "output": "json"}

    siblings: Set[str] = set()
    issuers: Set[str] = set()
    latest_date: str = ""
    cert_count = 0

    try:
        resp = httpx.get(url, headers=headers, params=params, timeout=10.0)
        if resp.status_code == 200:
            content_type = resp.headers.get("content-type", "")
            if "json" in content_type:
                data = resp.json()
            else:
                try:
                    data = resp.json()
                except Exception:
                    data = []

            if isinstance(data, list):
                cert_count = len(data)
                for item in data:
                    if not isinstance(item, dict):
                        continue
                    raw_issuer = str(item.get("issuer_name", ""))
                    m_iss = re.search(r"O=([^,]+)", raw_issuer)
                    if m_iss:
                        issuers.add(m_iss.group(1).strip().strip("'\""))
                    elif raw_issuer:
                        issuers.add(raw_issuer.split(",")[-1].strip().strip("'\""))

                    dt = str(item.get("not_before") or item.get("entry_timestamp") or "")
                    if dt and (not latest_date or dt > latest_date):
                        latest_date = dt[:10]

                    names = str(item.get("name_value", "")).splitlines()
                    cn = item.get("common_name")
                    if cn:
                        names.append(str(cn))

                    for n in names:
                        sub = n.strip().lower().lstrip("*.").strip(".")
                        if (
                            sub
                            and len(sub) >= 3
                            and sub != clean
                            and "." in sub
                            and not any(sub == pub or sub.endswith(f".{pub}") for pub in _KNOWN_PUBLISHER_DOMAINS)
                        ):
                            siblings.add(sub)
    except Exception:
        pass

    sorted_sibs = sorted(siblings)
    sorted_iss = sorted(issuers)
    parts = [f"Certificates: {cert_count} logged"]
    if sorted_iss:
        parts.append(f"CAs: {', '.join(sorted_iss[:2])}")
    if latest_date:
        parts.append(f"Latest: {latest_date}")
    if sorted_sibs:
        sample = ", ".join(sorted_sibs[:5])
        if len(sorted_sibs) > 5:
            sample += f" (+{len(sorted_sibs) - 5} more)"
        parts.append(f"Sibling Domains ({len(sorted_sibs)}): {sample}")
    else:
        parts.append("No sibling subdomains found")

    summary_str = " | ".join(parts)
    _CRTSH_CACHE[clean] = (now, summary_str, sorted_sibs)
    return sorted_sibs


def query_crtsh_domain(domain: str) -> str:
    """Query crt.sh Certificate Transparency logs for co-issued sibling subdomains and staging infrastructure."""
    clean = domain.strip().lower()
    now = time.monotonic()
    cached = _CRTSH_CACHE.get(clean)
    if cached and (now - cached[0] < _CRTSH_CACHE_TTL):
        return cached[1]

    apex = _get_apex_domain(clean)
    if any(clean.endswith(f".{suffix}") or clean == suffix for suffix in _SHARED_HOSTING_SUFFIXES):
        query_param = clean
    elif any(apex.endswith(f".{suffix}") or apex == suffix for suffix in _SHARED_HOSTING_SUFFIXES):
        query_param = clean
    else:
        query_param = f"%.{apex}" if apex else clean

    url = "https://crt.sh/"
    headers = {"Accept": "application/json", "User-Agent": "Hecate-Agent/2.0 (Threat-Hunting)"}
    params = {"q": query_param, "output": "json"}

    try:
        resp = httpx.get(url, headers=headers, params=params, timeout=10.0)
        if resp.status_code == 200:
            content_type = resp.headers.get("content-type", "")
            if "json" in content_type:
                data = resp.json()
            else:
                try:
                    data = resp.json()
                except Exception:
                    data = []

            if not isinstance(data, list) or not data:
                res = "No certificates found on crt.sh."
                _CRTSH_CACHE[clean] = (now, res, [])
                return res

            siblings: Set[str] = set()
            issuers: Set[str] = set()
            latest_date: str = ""

            for item in data:
                if not isinstance(item, dict):
                    continue
                raw_issuer = str(item.get("issuer_name", ""))
                m_iss = re.search(r"O=([^,]+)", raw_issuer)
                if m_iss:
                    issuers.add(m_iss.group(1).strip().strip("'\""))
                elif raw_issuer:
                    issuers.add(raw_issuer.split(",")[-1].strip().strip("'\""))

                dt = str(item.get("not_before") or item.get("entry_timestamp") or "")
                if dt and (not latest_date or dt > latest_date):
                    latest_date = dt[:10]

                names = str(item.get("name_value", "")).splitlines()
                cn = item.get("common_name")
                if cn:
                    names.append(str(cn))

                for n in names:
                    sub = n.strip().lower().lstrip("*.").strip(".")
                    if (
                        sub
                        and len(sub) >= 3
                        and sub != clean
                        and "." in sub
                        and not any(sub == pub or sub.endswith(f".{pub}") for pub in _KNOWN_PUBLISHER_DOMAINS)
                    ):
                        siblings.add(sub)

            sorted_sibs = sorted(siblings)
            sorted_iss = sorted(issuers)
            parts = [f"Certificates: {len(data)} logged"]
            if sorted_iss:
                parts.append(f"CAs: {', '.join(sorted_iss[:2])}")
            if latest_date:
                parts.append(f"Latest: {latest_date}")
            if sorted_sibs:
                sample = ", ".join(sorted_sibs[:5])
                if len(sorted_sibs) > 5:
                    sample += f" (+{len(sorted_sibs) - 5} more)"
                parts.append(f"Sibling Domains ({len(sorted_sibs)}): {sample}")
            else:
                parts.append("No sibling subdomains found")

            res = " | ".join(parts)
            _CRTSH_CACHE[clean] = (now, res, sorted_sibs)
            return res
        elif resp.status_code == 429:
            return "crt.sh rate limit exceeded."
        return f"crt.sh error: HTTP {resp.status_code}"
    except Exception as e:
        return f"Error querying crt.sh: {e}"


def query_epss(cve: str) -> str:
    """Query FIRST EPSS API for vulnerability exploit prediction probability and percentile."""
    clean_cve = cve.strip().upper()
    if not re.match(r"^CVE-\d{4}-\d{4,7}$", clean_cve):
        return f"Invalid CVE identifier '{cve}'."
    try:
        url = f"https://api.first.org/data/v1/epss?cve={clean_cve}"
        resp = httpx.get(url, timeout=5.0)
        if resp.status_code == 200:
            data = resp.json().get("data", [])
            if data and isinstance(data, list):
                item = data[0]
                epss_val = float(item.get("epss", 0.0))
                perc_val = float(item.get("percentile", 0.0))
                date_val = item.get("date", "")
                epss_pct = epss_val * 100
                perc_pct = perc_val * 100
                if epss_val >= 0.70:
                    severity = "CRITICAL EXPLOIT PROBABILITY"
                elif epss_val >= 0.35:
                    severity = "HIGH EXPLOIT PROBABILITY"
                elif epss_val >= 0.10:
                    severity = "ELEVATED EXPLOIT PROBABILITY"
                else:
                    severity = "MODERATE/LOW EXPLOIT PROBABILITY"
                date_str = f" · Date: {date_val}" if date_val else ""
                return (
                    f"EPSS: {epss_pct:.2f}% ({severity}) · "
                    f"{perc_pct:.1f}th percentile{date_str}"
                )
            return f"No EPSS score published for {clean_cve}."
        return f"EPSS API HTTP {resp.status_code}"
    except Exception as e:
        return f"Error querying EPSS: {e}"


def query_epss_batch(cves: List[str]) -> Dict[str, str]:
    """Query FIRST EPSS API for multiple CVEs in a single HTTP request."""
    valid_cves = [c.strip().upper() for c in cves if re.match(r"^CVE-\d{4}-\d{4,7}$", c.strip().upper())]
    if not valid_cves:
        return {}
    results: Dict[str, str] = {}
    chunk = valid_cves[:30]
    try:
        url = f"https://api.first.org/data/v1/epss?cve={','.join(chunk)}"
        resp = httpx.get(url, timeout=7.0)
        if resp.status_code == 200:
            data = resp.json().get("data", [])
            for item in data:
                cve_id = item.get("cve", "").upper()
                if not cve_id:
                    continue
                epss_val = float(item.get("epss", 0.0))
                perc_val = float(item.get("percentile", 0.0))
                date_val = item.get("date", "")
                epss_pct = epss_val * 100
                perc_pct = perc_val * 100
                if epss_val >= 0.70:
                    severity = "CRITICAL EXPLOIT PROBABILITY"
                elif epss_val >= 0.35:
                    severity = "HIGH EXPLOIT PROBABILITY"
                elif epss_val >= 0.10:
                    severity = "ELEVATED EXPLOIT PROBABILITY"
                else:
                    severity = "MODERATE/LOW EXPLOIT PROBABILITY"
                date_str = f" · Date: {date_val}" if date_val else ""
                results[cve_id] = (
                    f"EPSS: {epss_pct:.2f}% ({severity}) · "
                    f"{perc_pct:.1f}th percentile{date_str}"
                )
        for c in chunk:
            if c not in results:
                results[c] = f"No EPSS score published for {c}."
    except Exception as e:
        for c in chunk:
            results[c] = f"Error querying EPSS: {e}"
    return results


def query_osv_vuln(vuln_id: str) -> str:
    """Query OSV.dev (Google / OpenSSF Open Source Vulnerabilities) API for advisory details, affected packages, and severity."""
    clean_id = vuln_id.strip()
    if not clean_id:
        return "Invalid vulnerability ID."
    try:
        url = f"https://api.osv.dev/v1/vulns/{clean_id}"
        resp = httpx.get(url, timeout=5.0)
        if resp.status_code == 200:
            data = resp.json()
            summary = (data.get("summary") or "").strip()
            if not summary:
                details = (data.get("details") or "").strip()
                if details:
                    summary = details.split("\n")[0].strip()
            if summary and len(summary) > 120:
                summary = summary[:117] + "..."

            aliases = [a for a in data.get("aliases") or [] if isinstance(a, str) and a != clean_id]

            packages = []
            for aff in data.get("affected") or []:
                if isinstance(aff, dict):
                    pkg_info = aff.get("package") or {}
                    pname = pkg_info.get("name")
                    peco = pkg_info.get("ecosystem")
                    if pname:
                        formatted = f"{peco}:{pname}" if peco else str(pname)
                        if formatted not in packages:
                            packages.append(formatted)

            cvss = None
            for sev in data.get("severity") or []:
                if isinstance(sev, dict) and sev.get("score"):
                    cvss = sev.get("score")
                    break

            parts = []
            if summary:
                parts.append(f"Advisory: {summary}")
            if packages:
                pkg_str = ", ".join(packages[:3])
                if len(packages) > 3:
                    pkg_str += f" (+{len(packages)-3} more)"
                parts.append(f"Affected: {pkg_str}")
            if aliases:
                parts.append(f"Aliases: {', '.join(aliases[:3])}")
            if cvss:
                parts.append(f"CVSS: {cvss}")

            return " | ".join(parts) if parts else "Advisory cataloged on OSV.dev."
        elif resp.status_code == 404:
            return "No open-source advisory on OSV.dev."
        return f"OSV.dev error: HTTP {resp.status_code}"
    except Exception as e:
        return f"Error querying OSV.dev: {e}"


def query_otx_indicator(indicator_type: str, indicator: str) -> str:
    """Query AlienVault OTX Direct API for indicator general metadata, pulse associations, adversaries, and passive DNS.

    Supported indicator_type values: 'IPv4', 'domain', 'file', 'cve'.
    """
    key = _setting("OTX_API_KEY") or _setting("HECATE_RUNNER_OTX_API_KEY")
    if not key:
        return "OTX_API_KEY not configured."

    headers = {
        "X-OTX-API-KEY": key,
        "Accept": "application/json",
    }
    norm_type = indicator_type.strip()
    clean_val = indicator.strip()

    if norm_type.lower() in ("ip", "ipv4"):
        norm_type = "IPv4"
    elif norm_type.lower() in ("domain", "hostname"):
        norm_type = "domain"
        clean_val = clean_val.removeprefix("http://").removeprefix("https://").split("/")[0]
    elif norm_type.lower() in ("hash", "file", "sha256", "sha1", "md5"):
        norm_type = "file"
        clean_val = clean_val.lower()
    elif norm_type.lower() in ("cve", "vulnerability"):
        norm_type = "cve"
        clean_val = clean_val.upper()

    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/{norm_type}/{clean_val}/general"
        resp = httpx.get(url, headers=headers, timeout=5.0)
        if resp.status_code == 200:
            data = resp.json()
            pulse_info = data.get("pulse_info") or {}
            cnt = int(pulse_info.get("count", 0))
            pulses = pulse_info.get("pulses") or []

            adversaries: List[str] = []
            for p in pulses:
                adv = p.get("adversary")
                if adv and isinstance(adv, str):
                    adv_clean = adv.strip()
                    if adv_clean and adv_clean.lower() != "unknown" and adv_clean not in adversaries:
                        adversaries.append(adv_clean)

            titles: List[str] = [
                str(p.get("name")).strip()
                for p in pulses
                if p.get("name") and str(p.get("name")).strip()
            ]

            tags: List[str] = []
            for p in pulses:
                for t in p.get("tags") or []:
                    if t and isinstance(t, str):
                        t_clean = t.strip()
                        if t_clean and t_clean not in tags:
                            tags.append(t_clean)

            # For IPs and domains, attempt a quick passive DNS query to get correlated hostnames
            pdns_hosts: List[str] = []
            if norm_type in ("IPv4", "domain"):
                try:
                    pdns_url = f"https://otx.alienvault.com/api/v1/indicators/{norm_type}/{clean_val}/passive_dns"
                    pdns_resp = httpx.get(pdns_url, headers=headers, timeout=3.0)
                    if pdns_resp.status_code == 200:
                        entries = pdns_resp.json().get("passive_dns") or []
                        for e in entries:
                            h = e.get("hostname") or e.get("address")
                            if h and isinstance(h, str) and h not in pdns_hosts and h.lower() != clean_val.lower():
                                pdns_hosts.append(h)
                                if len(pdns_hosts) >= 2:
                                    break
                except Exception:
                    pass

            parts: List[str] = []
            if cnt > 0:
                p_desc = f"{cnt} Pulse(s)"
                if titles:
                    p_desc += f" (e.g. '{titles[0]}')"
                parts.append(p_desc)
                if adversaries:
                    parts.append(f"Adversary: {', '.join(adversaries[:2])}")
                if tags:
                    parts.append(f"Tags: {', '.join(tags[:3])}")
                if pdns_hosts:
                    parts.append(f"Passive DNS: {', '.join(pdns_hosts)}")
                return " | ".join(parts)
            else:
                if pdns_hosts:
                    return f"0 Pulses | Passive DNS: {', '.join(pdns_hosts)}"
                return "Not observed in OTX Pulses."
        elif resp.status_code == 404:
            return "No record on OTX."
        elif resp.status_code in (401, 403):
            return "OTX Auth Error (check OTX_API_KEY)."
        return f"OTX error: HTTP {resp.status_code}"
    except Exception as e:
        return f"Error querying OTX: {e}"


def query_otx_ip(ip: str) -> str:
    """Query AlienVault OTX Direct API for an IPv4 address."""
    return query_otx_indicator("IPv4", ip)


def query_otx_domain(domain: str) -> str:
    """Query AlienVault OTX Direct API for a domain."""
    return query_otx_indicator("domain", domain)


def query_otx_hash(file_hash: str) -> str:
    """Query AlienVault OTX Direct API for a file hash."""
    return query_otx_indicator("file", file_hash)


def query_otx_cve(cve: str) -> str:
    """Query AlienVault OTX Direct API for a CVE vulnerability."""
    return query_otx_indicator("cve", cve)


_PDNS_CACHE: Dict[str, Tuple[float, str, List[Dict[str, Any]]]] = {}
_PDNS_CACHE_TTL: float = 86400.0  # 24-hour cache TTL


def _normalize_pdns_timestamp(ts: Any) -> Optional[int]:
    """Normalize timestamp from VT (sec), Mnemonic (ms), or OTX (ISO string) into epoch seconds."""
    if not ts:
        return None
    if isinstance(ts, (int, float)):
        return int(ts / 1000) if ts > 1e11 else int(ts)
    if isinstance(ts, str):
        if ts.isdigit():
            val = int(ts)
            return int(val / 1000) if val > 1e11 else val
        try:
            clean = ts.replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean)
            return int(dt.timestamp())
        except Exception:
            return None
    return None


def _format_pdns_date(epoch_sec: Optional[int]) -> str:
    """Format epoch seconds into a concise YYYY-MM representation."""
    if not epoch_sec:
        return ""
    try:
        return datetime.fromtimestamp(epoch_sec, tz=timezone.utc).strftime("%Y-%m")
    except Exception:
        return ""


def query_vt_pdns_domain(domain: str) -> List[Dict[str, Any]]:
    """Query VirusTotal v3 for domain passive DNS resolutions."""
    key = _setting("VT_API_KEY") or _setting("HECATE_RUNNER_VT_API_KEY")
    if not key:
        return []
    clean_domain = domain.strip().lower()
    url = f"https://www.virustotal.com/api/v3/domains/{clean_domain}/resolutions"
    headers = {"x-apikey": key, "Accept": "application/json"}
    try:
        resp = httpx.get(url, headers=headers, timeout=5.0)
        if resp.status_code == 200:
            entries = []
            for item in resp.json().get("data", []):
                attr = item.get("attributes", {})
                ip = attr.get("ip_address")
                date_val = attr.get("date")
                if ip:
                    entries.append({"value": ip, "date": date_val, "source": "VT"})
            return entries
    except Exception:
        pass
    return []


def query_vt_pdns_ip(ip: str) -> List[Dict[str, Any]]:
    """Query VirusTotal v3 for IP passive DNS resolutions."""
    key = _setting("VT_API_KEY") or _setting("HECATE_RUNNER_VT_API_KEY")
    if not key:
        return []
    clean_ip = refang(ip).strip()
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{clean_ip}/resolutions"
    headers = {"x-apikey": key, "Accept": "application/json"}
    try:
        resp = httpx.get(url, headers=headers, timeout=5.0)
        if resp.status_code == 200:
            entries = []
            for item in resp.json().get("data", []):
                attr = item.get("attributes", {})
                host = attr.get("host_name")
                date_val = attr.get("date")
                if host:
                    entries.append({"value": host, "date": date_val, "source": "VT"})
            return entries
    except Exception:
        pass
    return []


def query_mnemonic_pdns(indicator: str, is_ip: bool = False) -> List[Dict[str, Any]]:
    """Query Mnemonic PDNS v3 public keyless API (with optional Argus key) for resolutions."""
    clean = refang(indicator).strip()
    if not clean:
        return []
    url = f"https://api.mnemonic.no/pdns/v3/{clean}?limit=25"
    headers = {"Accept": "application/json"}
    argus_key = _setting("MNEMONIC_API_KEY")
    if argus_key:
        headers["Argus-API-Key"] = argus_key
    try:
        resp = httpx.get(url, headers=headers, timeout=5.0)
        if resp.status_code == 200:
            entries = []
            for item in resp.json().get("data", []):
                val = item.get("query") if is_ip else item.get("answer")
                ts = item.get("lastSeenTimestamp") or item.get("lastUpdatedTimestamp")
                if val:
                    entries.append({"value": val, "date": ts, "source": "Mnemonic"})
            return entries
    except Exception:
        pass
    return []


def query_otx_pdns(indicator: str, is_ip: bool = False) -> List[Dict[str, Any]]:
    """Query AlienVault OTX Passive DNS endpoint for resolutions."""
    key = _setting("OTX_API_KEY")
    if not key:
        return []
    clean = refang(indicator).strip()
    norm_type = "IPv4" if is_ip else "domain"
    url = f"https://otx.alienvault.com/api/v1/indicators/{norm_type}/{clean}/passive_dns"
    headers = {"X-OTX-API-KEY": key, "Accept": "application/json"}
    try:
        resp = httpx.get(url, headers=headers, timeout=5.0)
        if resp.status_code == 200:
            entries = []
            for item in resp.json().get("passive_dns", []):
                val = item.get("hostname") if is_ip else item.get("address")
                ts = item.get("last")
                if val:
                    entries.append({"value": val, "date": ts, "source": "OTX"})
            return entries
    except Exception:
        pass
    return []


def query_passive_dns(indicator: str, max_results: int = 8) -> str:
    """Unified multi-source Passive DNS aggregator (VirusTotal, Mnemonic, AlienVault OTX).

    Returns historical resolved IPs for a domain, or correlated resolving hostnames for an IP.
    """
    clean = refang(indicator).strip()
    if not clean:
        return "No passive DNS records found."

    is_ip = False
    try:
        addr = ipaddress.ip_address(clean)
        is_ip = True
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return "Private/internal IP address."
    except ValueError:
        is_ip = False

    cache_prefix = "ip" if is_ip else "domain"
    cache_key = f"{cache_prefix}:{clean.lower()}"
    now = time.time()
    cached = _PDNS_CACHE.get(cache_key)
    if cached and (now - cached[0] < _PDNS_CACHE_TTL):
        return cached[1]

    all_entries: List[Dict[str, Any]] = []

    # Query VT
    if is_ip:
        all_entries.extend(query_vt_pdns_ip(clean))
    else:
        all_entries.extend(query_vt_pdns_domain(clean))

    # Query Mnemonic (Public keyless)
    all_entries.extend(query_mnemonic_pdns(clean, is_ip=is_ip))

    # Query OTX
    all_entries.extend(query_otx_pdns(clean, is_ip=is_ip))

    records: Dict[str, Dict[str, Any]] = {}
    for entry in all_entries:
        val = (entry.get("value") or "").strip()
        if not val or val.lower() == clean.lower() or val.endswith(".arpa"):
            continue
        val_norm = val.lower()
        ts = _normalize_pdns_timestamp(entry.get("date"))
        source = entry.get("source", "PDNS")
        if val_norm not in records:
            records[val_norm] = {
                "display": val,
                "timestamp": ts,
                "sources": {source},
            }
        else:
            records[val_norm]["sources"].add(source)
            if ts and (records[val_norm]["timestamp"] is None or ts > records[val_norm]["timestamp"]):
                records[val_norm]["timestamp"] = ts

    if not records:
        res = "No passive DNS records found."
        _PDNS_CACHE[cache_key] = (now, res, [])
        return res

    sorted_records = sorted(
        records.values(),
        key=lambda x: (x["timestamp"] is not None, x["timestamp"] or 0),
        reverse=True,
    )

    items = []
    sources_used: Set[str] = set()
    for r in sorted_records[:max_results]:
        d = f" ({_format_pdns_date(r['timestamp'])})" if r["timestamp"] else ""
        items.append(f"{r['display']}{d}")
        sources_used.update(r["sources"])

    src_str = f" [via {', '.join(sorted(sources_used))}]" if sources_used else ""
    summary = f"Passive DNS: {', '.join(items)}{src_str}"
    _PDNS_CACHE[cache_key] = (now, summary, sorted_records)
    return summary


def query_passive_dns_ip(ip: str, max_results: int = 8) -> str:
    """Convenience wrapper for IP passive DNS lookup."""
    return query_passive_dns(ip, max_results=max_results)


def query_passive_dns_domain(domain: str, max_results: int = 8) -> str:
    """Convenience wrapper for Domain passive DNS lookup."""
    return query_passive_dns(domain, max_results=max_results)


def query_hybrid_analysis(file_hash: str) -> str:
    """Query Hybrid Analysis (CrowdStrike Falcon Sandbox) API v2 for hash detonation results, threat score, and MITRE techniques."""
    key = (
        _setting("HYBRID_ANALYSIS_API_KEY")
        or _setting("HA_API_KEY")
        or _setting("FALCON_SANDBOX_API_KEY")
    )
    if not key:
        return "HYBRID_ANALYSIS_API_KEY not configured."

    clean_hash = file_hash.strip().lower()
    if not re.match(r"^[a-f0-9]{32,64}$", clean_hash):
        return f"Invalid hash format '{file_hash}'."

    headers = {
        "api-key": key,
        "User-Agent": "Falcon Sandbox",
        "Accept": "application/json",
    }

    try:
        url = f"https://hybrid-analysis.com/api/v2/overview/{clean_hash}"
        resp = httpx.get(url, headers=headers, timeout=5.0)
        if resp.status_code == 200:
            data = resp.json()
            if not isinstance(data, dict) or not data:
                return "No records on Hybrid Analysis."

            score = data.get("threat_score")
            verdict = data.get("verdict")
            vx_family = data.get("vx_family")
            ftype = data.get("type_short") or data.get("type")
            if isinstance(ftype, list):
                ftype = ftype[0] if ftype else "unknown"
            multiscan = data.get("multiscan_result")
            reports = data.get("reports") or []

            env = None
            mitre_ids: List[str] = []

            # If execution reports exist, fetch the primary report summary for dynamic environment & MITRE ATT&CK
            if reports and isinstance(reports, list):
                rep_id = str(reports[0]).strip()
                if rep_id:
                    try:
                        rep_url = f"https://hybrid-analysis.com/api/v2/report/{rep_id}/summary"
                        rep_resp = httpx.get(rep_url, headers=headers, timeout=4.0)
                        if rep_resp.status_code == 200:
                            r_json = rep_resp.json()
                            env = r_json.get("environment_description")
                            mitre_raw = r_json.get("mitre_attcks") or r_json.get("mitre_attcs") or []
                            for m in mitre_raw:
                                if isinstance(m, dict):
                                    mid = m.get("attck_id") or m.get("id")
                                    if mid and str(mid) not in mitre_ids:
                                        mitre_ids.append(str(mid).strip())
                    except Exception:
                        pass

            parts = []
            if verdict:
                score_str = f" (Score: {score}/100)" if score is not None else ""
                parts.append(f"Verdict: {verdict.upper()}{score_str}")
            elif score is not None:
                parts.append(f"Threat Score: {score}/100")

            if vx_family:
                parts.append(f"Family: {vx_family}")
            if ftype:
                parts.append(f"Type: {ftype}")
            if multiscan is not None:
                parts.append(f"Multi-Scan: {multiscan}%")
            if env:
                parts.append(f"Env: {env}")
            if mitre_ids:
                parts.append(f"MITRE: {', '.join(mitre_ids[:3])}")

            return " | ".join(parts) if parts else "Sample analyzed on Hybrid Analysis."
        elif resp.status_code == 404:
            return "No records on Hybrid Analysis."
        elif resp.status_code in (401, 403):
            return "Hybrid Analysis Auth Error (check HYBRID_ANALYSIS_API_KEY)."
        elif resp.status_code == 429:
            return "Hybrid Analysis rate limit exceeded."
        return f"Hybrid Analysis error: HTTP {resp.status_code}"
    except Exception as e:
        return f"Error querying Hybrid Analysis: {e}"


def generate_enrichment_summary(threat_intel: str) -> str:
    """Extracts indicators and queries OSINT platforms, returning a markdown summary."""
    indicators = extract_indicators(threat_intel)
    if not any(indicators.values()):
        return ""

    summary = ["\n\n### 🛡️ Automated Threat Enrichment (VT, AlienVault OTX, URLScan.io, crt.sh, Passive DNS, Tor Project, IPinfo, Hybrid Analysis, Abuse.ch [ThreatFox, MalwareBazaar, Feodo, SSLBL, URLhaus], GreyNoise, AbuseIPDB, Shodan, Censys, RDAP, EPSS, OSV.dev & MISP)"]

    from concurrent.futures import ThreadPoolExecutor

    def process_hash(h: str) -> str:
        res = query_vt_hash(h)
        otx_res = query_otx_hash(h)
        ha_res = query_hybrid_analysis(h)
        mb_res = query_malwarebazaar(h)
        sslbl_res = query_sslbl_fingerprint(h)
        urlhaus_res = query_urlhaus_payload(h)
        threatfox_res = query_threatfox(h)
        misp_res = query_misp_indicator(h)
        lines = [
            f"- **Hash {h}**:\n"
            f"  - *VirusTotal:* {res}\n"
            f"  - *AlienVault OTX:* {otx_res}\n"
            f"  - *Hybrid Analysis (Falcon Sandbox):* {ha_res}\n"
            f"  - *Abuse.ch (MalwareBazaar):* {mb_res}"
        ]
        if len(h) in (32, 40):
            lines.append(f"  - *Abuse.ch (SSLBL Fingerprint):* {sslbl_res}")
        if not urlhaus_res.startswith("No payload on URLhaus"):
            lines.append(f"  - *Abuse.ch (URLhaus Payload):* {urlhaus_res}")
        lines.append(f"  - *Abuse.ch (ThreatFox):* {threatfox_res}")
        lines.append(f"  - *Internal MISP:* {misp_res}")
        return "\n".join(lines)

    def process_ip(ip: str) -> str:
        vt_res = query_vt_ip(ip)
        otx_res = query_otx_ip(ip)
        feodo_res = query_feodotracker_ip(ip)
        abuseipdb_res = query_abuseipdb_ip(ip)
        anon_res = query_anonymity_proxy_ip(ip)
        spur_res = query_spur_ip(ip)
        pdns_res = query_passive_dns(ip)
        gn_res = query_greynoise_ip(ip)
        shodan_res = query_shodan_ip(ip)
        censys_res = query_censys_ip(ip)
        threatfox_res = query_threatfox(ip)
        misp_res = query_misp_indicator(ip)
        lines = [
            f"- **IP {ip}**:\n"
            f"  - *VirusTotal:* {vt_res}\n"
            f"  - *AlienVault OTX:* {otx_res}\n"
            f"  - *Abuse.ch (Feodo Tracker C2):* {feodo_res}\n"
            f"  - *AbuseIPDB:* {abuseipdb_res}"
        ]
        if anon_res and not anon_res.startswith("Private") and not anon_res.startswith("Invalid"):
            lines.append(f"  - *Anonymity & Proxy (Tor / Hosting / VPN):* {anon_res}")
        if not spur_res.startswith("SPUR_API_KEY not configured"):
            lines.append(f"  - *Spur.us (Proxy & Infrastructure):* {spur_res}")
        if not pdns_res.startswith("No passive DNS records found"):
            lines.append(f"  - *Passive DNS (Historical Correlated Hostnames):* {pdns_res}")
        lines.extend([
            f"  - *GreyNoise:* {gn_res}",
            f"  - *Shodan:* {shodan_res}",
            f"  - *Censys:* {censys_res}",
            f"  - *Abuse.ch (ThreatFox):* {threatfox_res}",
            f"  - *Internal MISP:* {misp_res}"
        ])
        return "\n".join(lines)

    def process_domain(d: str) -> str:
        vt_res = query_vt_domain(d)
        otx_res = query_otx_domain(d)
        rdap_res = query_rdap_domain(d)
        urlscan_res = query_urlscan_domain(d)
        crtsh_res = query_crtsh_domain(d)
        pdns_res = query_passive_dns(d)
        urlhaus_res = query_urlhaus_host(d)
        threatfox_res = query_threatfox(d)
        misp_res = query_misp_indicator(d)
        lines = [
            f"- **Domain {d}**:\n"
            f"  - *VirusTotal:* {vt_res}\n"
            f"  - *AlienVault OTX:* {otx_res}\n"
            f"  - *RDAP (Domain Age & Registrar):* {rdap_res}"
        ]
        if not urlscan_res.startswith("Not indexed on URLScan"):
            lines.append(f"  - *URLScan.io (Web Lures & Staging):* {urlscan_res}")
        if not crtsh_res.startswith("No certificates found on crt.sh"):
            lines.append(f"  - *crt.sh (Certificate Transparency & Sibling Domains):* {crtsh_res}")
        if not pdns_res.startswith("No passive DNS records found"):
            lines.append(f"  - *Passive DNS (Historical IP Resolutions):* {pdns_res}")
        if not urlhaus_res.startswith("Not listed on URLhaus"):
            lines.append(f"  - *Abuse.ch (URLhaus Host):* {urlhaus_res}")
        lines.append(f"  - *Abuse.ch (ThreatFox):* {threatfox_res}")
        lines.append(f"  - *Internal MISP:* {misp_res}")
        return "\n".join(lines)

    def process_url(u: str) -> str:
        urlscan_res = query_urlscan_url(u)
        urlhaus_res = query_urlhaus_url(u)
        threatfox_res = query_threatfox(u)
        misp_res = query_misp_indicator(u)
        return (
            f"- **URL {u}**:\n"
            f"  - *URLScan.io (DOM & Web Lure Analysis):* {urlscan_res}\n"
            f"  - *Abuse.ch (URLhaus):* {urlhaus_res}\n"
            f"  - *Abuse.ch (ThreatFox):* {threatfox_res}\n"
            f"  - *Internal MISP:* {misp_res}"
        )

    with ThreadPoolExecutor(max_workers=10) as executor:
        hash_futures = {executor.submit(process_hash, h): h for h in indicators["hashes"][:5]}
        ip_futures = {executor.submit(process_ip, ip): ip for ip in indicators["ips"][:5]}
        domain_futures = {executor.submit(process_domain, d): d for d in indicators["domains"][:5]}
        url_futures = {executor.submit(process_url, u): u for u in indicators.get("urls", [])[:5]}

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

        url_results = {future: future.result() for future in url_futures}
        for u in indicators.get("urls", [])[:5]:
            for future, result in url_results.items():
                if url_futures[future] == u:
                    summary.append(result)
                    break

    cve_list = indicators.get("cves", [])[:5]
    if cve_list:
        epss_batch = query_epss_batch(cve_list)
        for cve in cve_list:
            epss_res = epss_batch.get(cve, "No EPSS score published.")
            otx_res = query_otx_cve(cve)
            misp_res = query_misp_indicator(cve)
            osv_res = query_osv_vuln(cve)
            summary.append(
                f"- **Vulnerability {cve}**:\n"
                f"  - *FIRST EPSS (Exploit Prediction):* {epss_res}\n"
                f"  - *OSV.dev (Open Source Supply Chain):* {osv_res}\n"
                f"  - *AlienVault OTX:* {otx_res}\n"
                f"  - *Internal MISP:* {misp_res}"
            )

    final_output = ""
    if len(summary) > 1:
        final_output += "\n".join(summary)

    ttp_summary = expand_ttps(threat_intel)
    if ttp_summary:
        final_output += "\n" + ttp_summary

    return final_output
