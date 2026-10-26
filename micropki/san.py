import ipaddress
import logging

from cryptography import x509

from .logger import log_event

logger = logging.getLogger("pki_audit")

SAN_TYPES = {"dns", "ip", "email", "uri"}

TEMPLATE_SAN_WHITELIST = {
    "server":       {"dns", "ip"},
    "client":       {"dns", "email"},
    "code_signing": {"dns", "uri"},
}


def _parse_one(raw: str) -> tuple[str, x509.GeneralName]:
    if ":" not in raw:
        raise ValueError(f"Invalid SAN entry (expected 'type:value'): {raw!r}")
    kind, value = raw.split(":", 1)
    kind = kind.strip().lower()
    value = value.strip()
    if kind not in SAN_TYPES:
        raise ValueError(f"Unsupported SAN type {kind!r}; allowed: {sorted(SAN_TYPES)}")
    if not value:
        raise ValueError(f"Empty SAN value for type {kind!r}")

    if kind == "dns":
        return kind, x509.DNSName(value)
    if kind == "ip":
        try:
            return kind, x509.IPAddress(ipaddress.ip_address(value))
        except ValueError as e:
            raise ValueError(f"Invalid IP address in SAN {raw!r}: {e}") from e
    if kind == "email":
        return kind, x509.RFC822Name(value)
    return kind, x509.UniformResourceIdentifier(value)


def parse_san(values: list[str], template: str) -> x509.SubjectAlternativeName | None:
    if not values:
        return None

    if template not in TEMPLATE_SAN_WHITELIST:
        raise ValueError(f"Unknown template {template!r}")

    whitelist = TEMPLATE_SAN_WHITELIST[template]
    general_names: list[x509.GeneralName] = []
    seen: set[tuple[str, str]] = set()

    for raw in values:
        kind, name = _parse_one(raw)
        if kind not in whitelist:
            raise ValueError(
                f"SAN type {kind!r} is not allowed for template {template!r}; "
                f"allowed: {sorted(whitelist)}"
            )
        key = (kind, str(name.value))
        if key in seen:
            log_event(logger, logging.WARNING, "Duplicate SAN entry skipped", san=raw)
            continue
        seen.add(key)
        general_names.append(name)

    log_event(logger, logging.INFO, "SAN parsed successfully",
              template=template, count=len(general_names))
    return x509.SubjectAlternativeName(general_names)
