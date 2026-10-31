"""Domain models and built-in DNS provider catalogue for Raider DNS."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from ipaddress import ip_address
from typing import Any


@dataclass(frozen=True, slots=True)
class DNSProvider:
    id: str
    name: str
    description: str
    primary: str
    secondary: str
    category: str
    doh_url: str | None = None
    dot_hostname: str | None = None
    website: str = ""

    @property
    def servers(self) -> list[str]:
        return [ip for ip in (self.primary, self.secondary) if ip]

    @property
    def supports_doh(self) -> bool:
        return bool(self.doh_url)

    def validate(self) -> None:
        for server in self.servers:
            ip_address(server)


PROVIDERS: tuple[DNSProvider, ...] = (
    DNSProvider(
        "cloudflare", "Cloudflare", "Fast public DNS with a privacy-focused resolver.",
        "1.1.1.1", "1.0.0.1", "Privacy & speed",
        "https://cloudflare-dns.com/dns-query", "one.one.one.one", "https://one.one.one.one/",
    ),
    DNSProvider(
        "google", "Google Public DNS", "Global public DNS service with broad availability.",
        "8.8.8.8", "8.8.4.4", "General purpose",
        "https://dns.google/dns-query", "dns.google", "https://developers.google.com/speed/public-dns",
    ),
    DNSProvider(
        "quad9", "Quad9", "Security-oriented resolver that blocks many known malicious domains.",
        "9.9.9.9", "149.112.112.112", "Security",
        "https://dns.quad9.net/dns-query", "dns.quad9.net", "https://quad9.net/",
    ),
    DNSProvider(
        "adguard", "AdGuard DNS", "Public DNS service with filtering options; this profile uses the default resolver.",
        "94.140.14.14", "94.140.15.15", "Filtering",
        "https://dns.adguard-dns.com/dns-query", "dns.adguard-dns.com", "https://adguard-dns.io/en/adguard-dns/overview.html",
    ),
    DNSProvider(
        "cleanbrowsing", "CleanBrowsing Family", "Family filtering resolver. Filtering behavior may affect some sites.",
        "185.228.168.168", "185.228.169.168", "Family filtering",
        "https://doh.cleanbrowsing.org/doh/family-filter/", "family-filter-dns.cleanbrowsing.org", "https://cleanbrowsing.org/filters/",
    ),
    DNSProvider(
        "opendns", "OpenDNS", "Established public DNS service with optional account-based filtering.",
        "208.67.222.222", "208.67.220.220", "General purpose",
        None, None, "https://www.opendns.com/",
    ),
    DNSProvider(
        "comodo", "Comodo Secure DNS", "Public resolver historically marketed for safer DNS lookups.",
        "8.26.56.26", "8.20.247.20", "Security",
        None, None, "https://www.comodo.com/",
    ),
    DNSProvider(
        "shecan", "Shecan", "Public resolver commonly used for regional access and filtering differences.",
        "178.22.122.100", "185.51.200.2", "Regional",
        None, None, "https://shecan.ir/",
    ),
)

PROVIDER_BY_ID = {provider.id: provider for provider in PROVIDERS}


def provider_to_dict(provider: DNSProvider) -> dict[str, Any]:
    return asdict(provider)
