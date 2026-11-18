"""
AEGIS MCP Tool Guardrails & Scope Enforcement
Ensures:
1. Target ownership verification in DB before ANY active tool can touch it.
2. Scope limits: No destructive scan modes, strict request rate limits, and maximum duration timeouts.
"""

import re
import urllib.parse
from typing import Optional, Tuple, Dict, Any, List
from sqlalchemy import select
from app.core.database import AsyncSessionLocal
from app.models.domain import TargetAsset, VerificationStatus

# Destructive keyword blacklist
DISALLOWED_PATTERNS = [
    r"\bexploit\b",
    r"\bdos\b",
    r"\bddos\b",
    r"\bfuzz\b",
    r"\bbrute\b",
    r"\bdestructive\b",
    r"--script[=\s]+.*exploit",
    r"--script[=\s]+.*dos",
    r"-T5\b",
    r"--os-shell",
    r"\bdrop\s+database\b",
    r"\brm\s+-rf\b",
]

DEFAULT_MAX_DURATION_SECONDS = 180
ABSOLUTE_MAX_DURATION_SECONDS = 300

class GuardrailViolation(Exception):
    """Raised when a tool call violates scope, rate limit, or authorization rules."""
    def __init__(self, message: str, code: str = "SCOPE_VIOLATION", details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.code = code
        self.details = details or {}

def extract_domain(target: str) -> str:
    """
    Extracts a clean hostname / domain from URLs, IP addresses, or domain strings.
    Examples:
      'https://api.example.com:8443/v1' -> 'api.example.com'
      'http://127.0.0.1:8000' -> '127.0.0.1'
      'target.local/path' -> 'target.local'
      'scanme.nmap.org' -> 'scanme.nmap.org'
    """
    target = target.strip()
    if not target.startswith(("http://", "https://")):
        # Prepend scheme for urlparse if missing
        parsed = urllib.parse.urlparse("//" + target)
    else:
        parsed = urllib.parse.urlparse(target)
    
    hostname = parsed.hostname or target.split("/")[0].split(":")[0]
    return hostname.lower().strip()

async def check_target_ownership(target: str) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """
    Queries the AEGIS database to verify if the target domain has been verified
    via DNS TXT or HTML Meta tag verification.
    """
    clean_domain = extract_domain(target)
    if not clean_domain:
        return False, "Target address could not be parsed into a valid hostname.", None

    async with AsyncSessionLocal() as session:
        # Search for exact match or parent domain
        query = select(TargetAsset).where(TargetAsset.domain == clean_domain)
        result = await session.execute(query)
        target_asset = result.scalars().first()

        # If not found directly, check if target is a subdomain of a verified asset
        if not target_asset and "." in clean_domain:
            parts = clean_domain.split(".")
            for i in range(1, len(parts) - 1):
                parent_domain = ".".join(parts[i:])
                parent_query = select(TargetAsset).where(
                    TargetAsset.domain == parent_domain,
                    TargetAsset.verification_status == VerificationStatus.VERIFIED
                )
                parent_res = await session.execute(parent_query)
                target_asset = parent_res.scalars().first()
                if target_asset:
                    break

        if not target_asset:
            return False, f"Target '{clean_domain}' is NOT registered in AEGIS target assets.", None

        if target_asset.verification_status != VerificationStatus.VERIFIED:
            return (
                False,
                f"Target '{clean_domain}' is registered but NOT verified (Status: {target_asset.verification_status.value}). "
                f"Ownership verification via {target_asset.verification_method.value} is required.",
                {
                    "target_id": target_asset.id,
                    "domain": target_asset.domain,
                    "status": target_asset.verification_status.value,
                    "method": target_asset.verification_method.value
                }
            )

        return (
            True,
            f"Target '{clean_domain}' ownership verified successfully via {target_asset.verification_method.value}.",
            {
                "target_id": target_asset.id,
                "domain": target_asset.domain,
                "status": target_asset.verification_status.value,
                "verified_at": target_asset.last_verified_at.isoformat() if target_asset.last_verified_at else None
            }
        )

def validate_scope_limits(
    target: str,
    parameters: Optional[Dict[str, Any]] = None,
    requested_duration: Optional[int] = None,
    requested_rate_limit: Optional[int] = None,
    max_rate_allowed: int = 100
) -> Dict[str, Any]:
    """
    Enforces scope limits:
    - Rejects destructive flags or scan types.
    - Clamps/validates rate limits.
    - Enforces duration limits.
    """
    violations: List[str] = []

    # Check for destructive keywords in parameters
    if parameters:
        for k, v in parameters.items():
            str_val = str(v).lower()
            for pattern in DISALLOWED_PATTERNS:
                if re.search(pattern, str_val, re.IGNORECASE):
                    violations.append(f"Disallowed destructive pattern matched '{pattern}' in parameter '{k}'.")

    # Duration check
    duration = requested_duration or DEFAULT_MAX_DURATION_SECONDS
    if duration > ABSOLUTE_MAX_DURATION_SECONDS:
        violations.append(
            f"Requested duration {duration}s exceeds maximum permitted scan window of {ABSOLUTE_MAX_DURATION_SECONDS}s."
        )

    # Rate limit check
    rate_limit = requested_rate_limit
    if rate_limit is not None:
        if rate_limit <= 0:
            violations.append("Rate limit must be greater than 0.")
        elif rate_limit > max_rate_allowed:
            violations.append(
                f"Requested rate limit {rate_limit} req/s exceeds platform threshold of {max_rate_allowed} req/s."
            )
    else:
        rate_limit = min(max_rate_allowed, 50)

    if violations:
        raise GuardrailViolation("; ".join(violations), code="SCOPE_POLICY_VIOLATION", details={"violations": violations})

    return {
        "duration_seconds": min(duration, ABSOLUTE_MAX_DURATION_SECONDS),
        "rate_limit": rate_limit,
        "clean_target": extract_domain(target)
    }

async def enforce_active_scan_guardrails(
    target: str,
    parameters: Optional[Dict[str, Any]] = None,
    max_duration_seconds: Optional[int] = None,
    rate_limit: Optional[int] = None,
    max_rate_allowed: int = 100
) -> Tuple[bool, Dict[str, Any]]:
    """
    Unified gatekeeper for active scanning tools.
    1. Checks ownership verification against database.
    2. Validates non-destructive scope and rate limits.
    Returns (allowed: bool, details: dict)
    """
    # 1. Ownership verification
    is_verified, msg, target_info = await check_target_ownership(target)
    if not is_verified:
        return False, {
            "status": "REFUSED",
            "error_type": "UNVERIFIED_TARGET_REFUSAL",
            "message": f"CTEM GUARDRAIL REFUSAL: {msg}",
            "target": target,
            "target_info": target_info
        }

    # 2. Scope limits
    try:
        scope = validate_scope_limits(
            target=target,
            parameters=parameters,
            requested_duration=max_duration_seconds,
            requested_rate_limit=rate_limit,
            max_rate_allowed=max_rate_allowed
        )
    except GuardrailViolation as gv:
        return False, {
            "status": "REFUSED",
            "error_type": gv.code,
            "message": f"CTEM GUARDRAIL REFUSAL: {str(gv)}",
            "target": target,
            "details": gv.details
        }

    return True, {
        "status": "AUTHORIZED",
        "target": scope["clean_target"],
        "duration_seconds": scope["duration_seconds"],
        "rate_limit": scope["rate_limit"],
        "target_info": target_info
    }
