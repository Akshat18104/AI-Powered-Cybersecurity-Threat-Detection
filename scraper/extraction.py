import re
import ipaddress
import iocextract
from email import message_from_string

def is_public_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local)
    except ValueError:
        return False

def extract_domain(address_str: str) -> str:
    match = re.search(r'2([\w.-]+)' , address_str)
    return match.group(1).lower().rstrip('>') if match else ''

def parse_email_metadata(raw_headers: str) -> dict:
    if not raw_headers or not raw_headers.strip():
        return{
            "origin_ip" : None,
            "from_domain" : None,
            "return_path_domain" : "",
            "spf_fail" : False,
            "dkim_fail" : False,
            "dmarc_fail" : False,
            "domain_mismatch" : False,
            "auth_penalty" : 0.0,
            "flags" : ["No Headers Found"]
        }
    msg = message_from_string(raw_headers)
    flag = []
    auth_penalty = 0.0
    received_hops = msg.get_all('Received', [])
    origin_ip = None
    ip_regex = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'

    for hop in received_hops:
        candidates = re.findall(ip_regex, hop)
        for ip in candidates:
            if is_public_ip(ip):
                origin_ip = ip
                break
        if origin_ip:
            break

    if not origin_ip:
        all_ips = list(iocextract.extract_ips(raw_headers))
        for ip in all_ips:
            if is_public_ip(ip):
                origin_ip = ip
                break

    auth_results = " ".join(msg.get_all('Authentication-Results', [])).lower()
    received_spf = msg.get("Recevied-SPF", "").lower()

    spf_fail = "spf = fail" in auth_results or "spf = softfail" in auth_results or "fail" in received_spf
    dkim_fail = "dkim = fail" in auth_results
    dmarc_fail = "dmarc = fail" in auth_results

    if spf_fail:
        auth_penalty += 0.15
        flag.append("SPF Validation Failed")
    if dkim_fail:
        auth_penalty += 0.10
        flag.append("DKIM Signature Failed")
    if dmarc_fail:
        auth_penalty += 0.20
        flag.append("DMARC Enforcment Failed")

    from_domain = extract_domain(msg.get("From", ""))
    return_domain = extract_domain(msg.get("Return-Path", ""))
    domain_mismatch = bool(from_domain and return_domain and from_domain != return_domain)

    if domain_mismatch:
        auth_penalty += 0.15
        flag.append(f"Domain Mismatch: From '@{from_domain}' vs Return-Path '@{return_domain}' ")

    return{
        "origin_ip" : origin_ip,
        "from_domain": from_domain,
        "return_path_domain" : return_domain,
        "spf_fail" : spf_fail,
        "dkim_fail" : dkim_fail,
        "dmarc_fail" : dmarc_fail,
        "domain_mismatch" : domain_mismatch,
        "auth_penalty" : min(auth_penalty, 0.40),
        "flags" : flag
    }
