import asyncio
import ipaddress
import dns.resolver
import httpx
import re
import hmac
import logging
import socket
from typing import Tuple, Optional
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

def _clean_domain_for_dns(domain: str) -> str:
    """Extract clean hostname without scheme, path, or port for DNS lookups."""
    clean = domain.strip().lower()
    for prefix in ["https://", "http://"]:
        if clean.startswith(prefix):
            clean = clean[len(prefix):]
    clean = clean.split("/")[0]
    clean = clean.split(":")[0]
    return clean

def _clean_domain_for_http(domain: str) -> str:
    """Extract clean host (with port if specified) for HTTP lookups."""
    candidate = domain.strip()
    parsed = urlsplit(candidate if "://" in candidate else f"https://{candidate}")
    return parsed.netloc


def _https_target(domain: str, path: str) -> Tuple[str, str]:
    candidate = domain.strip()
    parsed = urlsplit(candidate if "://" in candidate else f"https://{candidate}")
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("HTTPS verification requires a hostname without credentials, query, or fragment.")
    try:
        hostname = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        port = parsed.port
    except (UnicodeError, ValueError) as exc:
        raise ValueError("Invalid HTTPS verification hostname or port.") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Invalid verification port.")
    return hostname, f"https://{parsed.netloc}{path}"


async def _resolve_public_addresses(host: str) -> list[str]:
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None

    if literal is not None:
        return [str(literal)] if literal.is_global else []

    try:
        addresses = await asyncio.get_running_loop().getaddrinfo(
            host,
            None,
            type=socket.SOCK_STREAM,
        )
    except (OSError, socket.gaierror):
        return []

    resolved = set()
    for address in addresses:
        try:
            resolved.add(ipaddress.ip_address(address[4][0]))
        except ValueError:
            return []
    if not resolved or not all(address.is_global for address in resolved):
        return []
    return sorted(str(address) for address in resolved)


async def _fetch_public_https(
    domain: str,
    path: str,
    fallback_path: Optional[str] = None,
) -> Tuple[Optional[str], str]:
    try:
        host, url = _https_target(domain, path)
    except ValueError as exc:
        return None, str(exc)

    addresses = await _resolve_public_addresses(host)
    if not addresses:
        return None, "HTTPS verification target must resolve exclusively to public IP addresses."

    parsed_url = urlsplit(url)
    host_header = f"[{host}]" if ":" in host else host
    if parsed_url.port is not None:
        host_header = f"{host_header}:{parsed_url.port}"

    try:
        async with httpx.AsyncClient(
            timeout=10.0,
            follow_redirects=False,
            verify=True,
            trust_env=False,
        ) as client:
            response = None
            last_error = None
            for address in addresses:
                ip = ipaddress.ip_address(address)
                ip_host = f"[{ip}]" if ip.version == 6 else str(ip)
                netloc = ip_host
                if parsed_url.port is not None:
                    netloc = f"{netloc}:{parsed_url.port}"
                pinned_url = parsed_url._replace(netloc=netloc).geturl()
                try:
                    response = await client.get(
                        pinned_url,
                        headers={"Host": host_header},
                        extensions={"sni_hostname": host},
                    )
                    break
                except httpx.HTTPError as exc:
                    last_error = exc
            if response is None:
                return None, f"HTTPS verification request failed: {last_error}"
            if response.status_code == 404 and fallback_path:
                fallback_host, fallback_url = _https_target(domain, fallback_path)
                if fallback_host != host:
                    return None, "HTTPS verification fallback changed the target hostname."
                fallback = urlsplit(fallback_url)
                fallback_pinned_url = fallback._replace(netloc=netloc).geturl()
                response = await client.get(
                    fallback_pinned_url,
                    headers={"Host": host_header},
                    extensions={"sni_hostname": host},
                )
    except httpx.HTTPError as exc:
        return None, f"HTTPS verification request failed: {exc}"

    if 300 <= response.status_code < 400:
        return None, "HTTPS verification redirects are not followed."
    if response.status_code != 200:
        return None, f"HTTPS verification returned HTTP {response.status_code}."
    return response.text, ""

async def verify_dns_txt_record(domain: str, expected_token: str) -> Tuple[bool, str]:
    """
    Query DNS TXT records for the domain looking strictly for:
    - 'rakshak-verification=<expected_token>' or 'aegis-verification=<expected_token>'
    - 'antigravity-verification=<expected_token>' (with deprecation warning)
    Compared using constant-time hmac.compare_digest.
    """
    clean_domain = _clean_domain_for_dns(domain)
    expected_token_clean = expected_token.strip()
    rakshak_entry = f"rakshak-verification={expected_token_clean}"
    aegis_entry = f"aegis-verification={expected_token_clean}"
    deprecated_entry = f"antigravity-verification={expected_token_clean}"

    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5.0
        resolver.lifetime = 5.0
        answers = resolver.resolve(clean_domain, 'TXT')

        for rdata in answers:
            for txt_string in rdata.strings:
                decoded = txt_string.decode('utf-8', errors='ignore').strip()
                # A TXT record can have multiple lines or quoted strings
                for raw_line in decoded.splitlines():
                    line = raw_line.strip().strip('"').strip("'")
                    if hmac.compare_digest(line, rakshak_entry) or hmac.compare_digest(line, aegis_entry):
                        return True, f"DNS TXT record matching verification token verified successfully on {clean_domain}."
                    if hmac.compare_digest(line, deprecated_entry):
                        logger.warning(
                            f"DEPRECATION WARNING: Host '{clean_domain}' verified using legacy format "
                            f"'antigravity-verification='. Please update DNS TXT record to 'rakshak-verification='."
                        )
                        return True, f"DNS TXT record matching '{deprecated_entry}' verified successfully on {clean_domain} (legacy format)."

        return False, f"DNS TXT verification failed: record 'rakshak-verification={expected_token_clean}' not found on {clean_domain}."
    except Exception as e:
        return False, f"DNS TXT lookup failed for {clean_domain} (error: {str(e)})"

async def verify_html_meta_tag(domain: str, expected_token: str) -> Tuple[bool, str]:
    """
    Fetch HTTP homepage and check strictly for:
    <meta name="rakshak-verification" content="<expected_token>"> or
    <meta name="aegis-verification" content="<expected_token>"> or
    <meta name="antigravity-verification" content="<expected_token>"> (with deprecation warning)
    Token compared using constant-time hmac.compare_digest.
    """
    expected_token_clean = expected_token.strip()
    html_content, error = await _fetch_public_https(domain, "/")
    if html_content is None:
        return False, error

    pattern_name_first = r'<meta\s+[^>]*name=["\'](rakshak-verification|aegis-verification|antigravity-verification)["\'][^>]*content=["\']([^"\']+)["\'][^>]*>'
    pattern_content_first = r'<meta\s+[^>]*content=["\']([^"\']+)["\'][^>]*name=["\'](rakshak-verification|aegis-verification|antigravity-verification)["\'][^>]*>'

    matches = re.findall(pattern_name_first, html_content, re.IGNORECASE)
    for tag_name, content in matches:
        if tag_name.lower() == "antigravity-verification":
            logger.warning(
                f"DEPRECATION WARNING: Website '{domain}' uses legacy meta tag name "
                f"'antigravity-verification'. Please migrate to 'rakshak-verification'."
            )
        if hmac.compare_digest(content.strip(), expected_token_clean):
            return True, f"HTML meta tag verified on https://{_clean_domain_for_http(domain)}."

    rev_matches = re.findall(pattern_content_first, html_content, re.IGNORECASE)
    for content, tag_name in rev_matches:
        if tag_name.lower() == "antigravity-verification":
            logger.warning(
                f"DEPRECATION WARNING: Website '{domain}' uses legacy meta tag name "
                f"'antigravity-verification'. Please migrate to 'rakshak-verification'."
            )
        if hmac.compare_digest(content.strip(), expected_token_clean):
            return True, f"HTML meta tag verified on https://{_clean_domain_for_http(domain)}."

    return False, f"HTML meta tag 'rakshak-verification' with token was not found on {domain}."

async def verify_well_known_file(domain: str, expected_token: str) -> Tuple[bool, str]:
    """
    Fetch the canonical well-known file, falling back to the legacy AEGIS path only on HTTP 404:
    'rakshak-verification=<expected_token>' or 'aegis-verification=<expected_token>' or
    'antigravity-verification=<expected_token>' (with deprecation warning).
    Compared using constant-time hmac.compare_digest.
    Enables verification on hosted platforms (Vercel, Netlify) without DNS access.
    """
    expected_token_clean = expected_token.strip()
    rakshak_entry = f"rakshak-verification={expected_token_clean}"
    aegis_entry = f"aegis-verification={expected_token_clean}"
    deprecated_entry = f"antigravity-verification={expected_token_clean}"

    text_content, error = await _fetch_public_https(
        domain,
        "/.well-known/rakshak-verification.txt",
        fallback_path="/.well-known/aegis-verification.txt",
    )
    if text_content is None:
        return False, error

    for raw_line in text_content.splitlines():
        line = raw_line.strip().strip('"').strip("'")
        if hmac.compare_digest(line, rakshak_entry) or hmac.compare_digest(line, aegis_entry):
            return True, f"Well-known verification file verified successfully for {domain}."
        if hmac.compare_digest(line, deprecated_entry):
            logger.warning(
                f"DEPRECATION WARNING: Verification file for '{domain}' uses legacy format "
                f"'antigravity-verification='. Please update to 'rakshak-verification='."
            )
            return True, f"Well-known verification file verified successfully for {domain} (legacy token format)."

    return False, f"No supported well-known verification token was found on {domain}."
