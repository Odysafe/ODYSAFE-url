from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from app.database import Database


@dataclass(frozen=True)
class Provider:
    id: str
    name: str
    profile: str
    capability: str
    method: str
    hostname: str | None
    path: str
    bootstrap: str
    secondary: str
    automatic_interpretation: bool


PROVIDERS = {
    item.id: item for item in (
        Provider("quad9", "Quad9 Secure", "secure", "supported", "doh",
                 "dns.quad9.net", "/dns-query", "9.9.9.9", "149.112.112.112", True),
        Provider("cloudflare_malware", "Cloudflare for Families", "malware", "supported", "doh",
                 "security.cloudflare-dns.com", "/dns-query", "1.1.1.2", "1.0.0.2", True),
        Provider("dns4eu_protective", "DNS4EU", "protective", "supported", "doh",
                 "protective.joindns4.eu", "/dns-query", "86.54.11.1", "86.54.11.201", True),
        Provider("cleanbrowsing_security", "CleanBrowsing", "security-filter", "supported", "doh",
                 "doh.cleanbrowsing.org", "/doh/security-filter/", "185.228.168.9", "185.228.169.9", True),
        Provider("controld_malware", "Control D", "free-malware-p1", "limited", "doh",
                 "freedns.controld.com", "/p1", "76.76.2.1", "76.76.10.1", False),
        Provider("opendns_public", "Cisco OpenDNS", "public", "limited", "doh",
                 "dns.opendns.com", "/dns-query", "208.67.222.222", "208.67.220.220", False),
    )
}


# Texte d'aide affiché dans les paramètres. Il décrit uniquement le profil
# effectivement configuré ci-dessus et les signaux interprétés par le moteur.
PROVIDER_SUMMARIES = {
    "opendns_public": {
        "coverage": "Protection DNS publique de base, notamment contre le phishing et certaines menaces.",
        "evidence": "La réponse est conservée. Une réponse négative isolée ne suffit pas à conclure à un signal de sécurité.",
    },
    "cleanbrowsing_security": {
        "coverage": "Filtrage des domaines associés aux malwares, au phishing et à d'autres menaces.",
        "evidence": "Un NXDOMAIN n'est retenu que si la résolution de référence indique que le domaine existe.",
    },
    "cloudflare_malware": {
        "coverage": "Profil Malware de Cloudflare for Families : malware et phishing.",
        "evidence": "Une réponse 0.0.0.0 constitue le signal de filtrage interprété automatiquement par ODYSAFE.",
    },
    "controld_malware": {
        "coverage": "Profil gratuit p1 destiné au filtrage des domaines associés aux malwares.",
        "evidence": "La réponse est conservée. Une réponse vide ou négative reste indéterminée sans preuve propre au fournisseur.",
    },
    "dns4eu_protective": {
        "coverage": "Profil Protective : malware, phishing et infrastructures de commande et contrôle.",
        "evidence": "ODYSAFE interprète les adresses de page d'avertissement documentées ; une réponse négative seule reste indéterminée.",
    },
    "quad9": {
        "coverage": "Profil Secure de Quad9 : protection contre les domaines associés à des menaces.",
        "evidence": "ODYSAFE conserve notamment les Extended DNS Errors de filtrage, dont EDE 17, et les réponses DNS associées.",
    },
}


def seed_providers(database: Database) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with database.transaction() as connection:
        for provider in PROVIDERS.values():
            connection.execute("""INSERT INTO threat_providers
              (id,name,profile,capability,enabled,method,updated_at) VALUES(?,?,?,?,0,?,?)
              ON CONFLICT(id) DO UPDATE SET name=excluded.name,profile=excluded.profile,
              capability=excluded.capability,method=excluded.method,updated_at=excluded.updated_at""",
              (provider.id, provider.name, provider.profile, provider.capability, provider.method, now))
        connection.execute("""INSERT OR IGNORE INTO app_settings(key,value,updated_at)
          VALUES('dns_external_enabled','true',?)""", (now,))
        connection.execute("""INSERT OR IGNORE INTO app_settings(key,value,updated_at)
          VALUES('dns_max_domains','25',?)""", (now,))
        connection.execute("""INSERT OR IGNORE INTO app_settings(key,value,updated_at)
          VALUES('dns_timeout_seconds','4',?)""", (now,))
        connection.execute("""INSERT OR IGNORE INTO app_settings(key,value,updated_at)
          VALUES('dns_auto_enabled','true',?)""", (now,))
        connection.execute("""INSERT OR IGNORE INTO app_settings(key,value,updated_at)
          VALUES('dns_concurrency','8',?)""", (now,))
        connection.execute("""INSERT OR IGNORE INTO app_settings(key,value,updated_at)
          VALUES('dns_cache_hours','24',?)""", (now,))


def public_provider(provider: Provider) -> dict:
    value = asdict(provider)
    value.pop("automatic_interpretation")
    return value
