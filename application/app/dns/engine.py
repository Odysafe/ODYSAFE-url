from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

import dns.edns
import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import httpx
import ssl

from .domains import normalize_public_domain
from .providers import PROVIDERS, Provider

POLICY_VERSION = "stage12-v3"
DNS4EU_WARNING_ADDRESSES = {
    "51.15.69.11",
    "2001:bc8:1640:3ffd:dc00:ff:fe4a:3ec9",
}


def _bounded_records(response_sections: list, item_limit: int, byte_limit: int) -> list[str]:
    records: list[str] = []
    used = 0
    for rrset in response_sections:
        for rr in rrset:
            value = rr.to_text()[:1024]
            encoded_size = len(value.encode("utf-8", errors="replace"))
            if len(records) >= item_limit or used + encoded_size > byte_limit:
                return records
            records.append(value)
            used += encoded_size
    return records


def _technical(response: dns.message.Message) -> tuple[str, list[str], list[str], list[dict[str, Any]]]:
    rcode = dns.rcode.to_text(response.rcode())
    answers = _bounded_records(response.answer, 50, 4096)
    authority = _bounded_records(response.authority, 20, 2048)
    ede = []
    for option in response.options:
        if isinstance(option, dns.edns.EDEOption):
            ede.append({"code": int(option.code), "text": str(option.text)[:500]})
            if len(ede) >= 10:
                break
    return rcode, answers, authority, ede


def interpret(provider: Provider, qtype: str, rcode: str, answers: list[str],
              authority: list[str], ede: list[dict[str, Any]],
              reference_rcode: str | None = None,
              reference_answers: list[str] | None = None) -> tuple[str, str]:
    ede_codes = {item["code"] for item in ede}
    if provider.id == "quad9" and ede_codes & {15, 16, 17}:
        return "blocked", f"Explicit Extended DNS Error code(s): {sorted(ede_codes & {15,16,17})}"
    if provider.id == "quad9" and rcode == "NXDOMAIN" and not authority:
        return "blocked", "Quad9 NXDOMAIN with an empty Authority section"
    if provider.id == "cloudflare_malware" and qtype == "A" and any(item.split()[-1] == "0.0.0.0" for item in answers):
        return "blocked", "Cloudflare malware profile returned the documented IPv4 sinkhole 0.0.0.0"
    if provider.id == "dns4eu_protective" and any(
            item.rstrip(".").split()[-1] in DNS4EU_WARNING_ADDRESSES for item in answers):
        return "blocked", "DNS4EU Protective returned its warning-page address instead of the destination address"
    if (provider.id == "cleanbrowsing_security" and rcode == "NXDOMAIN"
            and reference_rcode == "NOERROR" and reference_answers):
        return "blocked", "CleanBrowsing returned NXDOMAIN while the neutral reference resolver returned an address"
    if rcode == "NOERROR" and answers:
        if provider.automatic_interpretation:
            return "not_blocked_observed", "A DNS answer was observed; this is not a clean verdict"
        return "indeterminate", "Provider response recorded; automatic block interpretation is disabled"
    if rcode == "NXDOMAIN":
        return "indeterminate", "NXDOMAIN alone cannot distinguish filtering from non-existence"
    if rcode in {"SERVFAIL", "REFUSED", "FORMERR"}:
        return "indeterminate", f"{rcode} does not establish a security block"
    if rcode == "NOERROR":
        return "indeterminate", "NOERROR without address data does not establish a security block"
    return "error", f"Unhandled DNS response code {rcode}"


def query_one(provider_id: str, domain: str, qtype: str, timeout: float = 4.0) -> dict[str, Any]:
    provider = PROVIDERS[provider_id]; normalized = normalize_public_domain(domain)
    started = time.monotonic(); checked = datetime.now(timezone.utc).isoformat()
    base = {"domain": normalized, "provider_id": provider.id, "provider_profile": provider.profile,
            "method": provider.method, "qtype": qtype, "checked_at": checked,
            "policy_version": POLICY_VERSION}
    try:
        query = dns.message.make_query(normalized, dns.rdatatype.from_text(qtype), want_dnssec=True)
        if provider.method == "doh" or provider.hostname:
            endpoint = f"https://{provider.hostname}{provider.path}"
            response = dns.query.https(query, endpoint, timeout=timeout,
                                       bootstrap_address=provider.bootstrap,
                                       http_version=dns.query.HTTPVersion.HTTP_2)
        else:
            response = dns.query.udp(query, provider.bootstrap, timeout=timeout, ignore_unexpected=True)
            if response.flags & dns.flags.TC:
                response = dns.query.tcp(query, provider.bootstrap, timeout=timeout)
        rcode, answers, authority, ede = _technical(response)
        reference_rcode=None; reference_answers: list[str]=[]
        if provider.id=="cleanbrowsing_security" and rcode=="NXDOMAIN":
            try:
                reference=dns.query.https(query,"https://cloudflare-dns.com/dns-query",timeout=timeout,
                                          bootstrap_address="1.1.1.1",
                                          http_version=dns.query.HTTPVersion.HTTP_2)
                reference_rcode,reference_answers,_,_=_technical(reference)
            except (dns.exception.DNSException, httpx.HTTPError, ssl.SSLError, OSError):
                reference_rcode="REFERENCE_ERROR"
        status, justification = interpret(provider, qtype, rcode, answers, authority, ede,
                                           reference_rcode,reference_answers)
        return {**base, "duration_ms": int((time.monotonic()-started)*1000), "rcode": rcode,
                "answers": answers, "authority": authority, "ede": ede,
                "reference_rcode":reference_rcode,"reference_answers":reference_answers,
                "interpretation": status, "justification": justification, "error": None}
    except (dns.exception.DNSException, httpx.HTTPError, ssl.SSLError, OSError, ValueError) as exc:
        return {**base, "duration_ms": int((time.monotonic()-started)*1000), "rcode": None,
                "answers": [], "authority": [], "ede": [], "interpretation": "error",
                "reference_rcode":None,"reference_answers":[],
                "justification": "Provider query failed", "error": f"{type(exc).__name__}: {str(exc)[:500]}"}


def query_custom(provider_id: str, name: str, address: str, domain: str,
                 qtype: str, timeout: float = 4.0) -> dict[str, Any]:
    """Record a public custom resolver response without deriving a threat verdict."""
    normalized=normalize_public_domain(domain); started=time.monotonic()
    base={"domain":normalized,"provider_id":provider_id,"provider_profile":"custom-resolution",
          "method":"udp","qtype":qtype,"checked_at":datetime.now(timezone.utc).isoformat(),
          "policy_version":POLICY_VERSION}
    try:
        query=dns.message.make_query(normalized,dns.rdatatype.from_text(qtype),want_dnssec=True)
        response=dns.query.udp(query,address,timeout=timeout,ignore_unexpected=True)
        if response.flags & dns.flags.TC:
            response=dns.query.tcp(query,address,timeout=timeout)
        rcode,answers,authority,ede=_technical(response)
        return {**base,"duration_ms":int((time.monotonic()-started)*1000),"rcode":rcode,
                "answers":answers,"authority":authority,"ede":ede,"reference_rcode":None,
                "reference_answers":[],"interpretation":"indeterminate",
                "justification":f"Custom resolver {name}: response recorded without automatic security interpretation",
                "error":None}
    except (dns.exception.DNSException,OSError,ValueError) as exc:
        return {**base,"duration_ms":int((time.monotonic()-started)*1000),"rcode":None,
                "answers":[],"authority":[],"ede":[],"reference_rcode":None,"reference_answers":[],
                "interpretation":"error","justification":f"Custom resolver {name} query failed",
                "error":f"{type(exc).__name__}: {str(exc)[:500]}"}
