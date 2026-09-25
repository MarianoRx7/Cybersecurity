"""Verify cryptographically signed AI agents (Web Bot Auth).

Web Bot Auth is an IETF draft built on HTTP Message Signatures (RFC 9421).
A well-behaved agent sends:

    Signature-Agent: "https://agent.example"
    Signature-Input: sig1=("@authority" "signature-agent");created=...;expires=...;
                     keyid="...";alg="ed25519";tag="web-bot-auth"
    Signature:       sig1=:<base64 Ed25519 signature>:

A User-Agent string can be spoofed by anyone; a valid signature proves the
request came from the operator that holds the key. This module implements the
subset of RFC 9421 that Web Bot Auth uses, against a local key registry.
"""
import base64
import json
import re
import time
from dataclasses import dataclass

SUPPORTED_COMPONENTS = {"@authority", "@method", "@path", "signature-agent"}
_INPUT_RE = re.compile(r'^\s*([A-Za-z0-9_-]+)=(\(([^)]*)\)(.*))$')
_SIG_RE = re.compile(r'^\s*([A-Za-z0-9_-]+)=:([A-Za-z0-9+/=]+):\s*$')
_PARAM_RE = re.compile(r';([a-z]+)=("[^"]*"|\d+)')


class AgentAuthError(Exception):
    pass


@dataclass
class VerifiedAgent:
    keyid: str
    operator: str
    signature_agent: str


def load_registry(path: str) -> dict:
    try:
        with open(path) as fh:
            return json.load(fh).get("agents", {})
    except FileNotFoundError:
        return {}


def has_signature_headers(headers) -> bool:
    return bool(headers.get("Signature") and headers.get("Signature-Input"))


def _component_value(name: str, headers, method: str, path: str) -> str:
    if name == "@authority":
        return (headers.get("Host") or "").lower()
    if name == "@method":
        return method.upper()
    if name == "@path":
        return path.split("?", 1)[0]
    value = headers.get(name)
    if value is None:
        raise AgentAuthError(f"signed header {name!r} missing")
    return value.strip()


def verify_request(headers, method: str, path: str, registry: dict,
                   max_age: int = 3600, clock=time.time) -> VerifiedAgent:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    m_input = _INPUT_RE.match(headers.get("Signature-Input") or "")
    m_sig = _SIG_RE.match(headers.get("Signature") or "")
    if not m_input or not m_sig or m_input.group(1) != m_sig.group(1):
        raise AgentAuthError("missing or mismatched signature headers")

    signature_params = m_input.group(2)
    components = re.findall(r'"([^"]+)"', m_input.group(3))
    params = {k: v.strip('"') for k, v in _PARAM_RE.findall(m_input.group(4))}

    if params.get("tag") != "web-bot-auth":
        raise AgentAuthError("signature is not tagged web-bot-auth")
    if params.get("alg", "ed25519") != "ed25519":
        raise AgentAuthError("unsupported signature algorithm")
    if "@authority" not in components:
        raise AgentAuthError("signature must cover @authority")
    if not set(components) <= SUPPORTED_COMPONENTS:
        raise AgentAuthError("signature covers unsupported components")

    now = clock()
    try:
        created, expires = int(params["created"]), int(params["expires"])
    except (KeyError, ValueError):
        raise AgentAuthError("signature must carry created and expires")
    if created > now + 60 or expires <= now or expires - created > max_age:
        raise AgentAuthError("signature outside its validity window")

    entry = registry.get(params.get("keyid", ""))
    if not entry:
        raise AgentAuthError("unknown signing key")

    lines = [f'"{c}": {_component_value(c, headers, method, path)}' for c in components]
    lines.append(f'"@signature-params": {signature_params}')
    base = "\n".join(lines).encode()

    try:
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(entry["public_key"]))
        key.verify(base64.b64decode(m_sig.group(2)), base)
    except (InvalidSignature, ValueError):
        raise AgentAuthError("signature verification failed")

    return VerifiedAgent(
        keyid=params["keyid"],
        operator=entry.get("operator", "unknown"),
        signature_agent=(headers.get("Signature-Agent") or "").strip('"'),
    )


def sign_request(private_key, keyid: str, authority: str, signature_agent: str,
                 created: int | None = None, ttl: int = 300) -> dict:
    """Produce Web Bot Auth headers. Used by tests and the demo agent client."""
    created = int(created if created is not None else time.time())
    agent_header = f'"{signature_agent}"'
    params = (f'("@authority" "signature-agent");created={created};expires={created + ttl};'
              f'keyid="{keyid}";alg="ed25519";tag="web-bot-auth"')
    base = (f'"@authority": {authority.lower()}\n"signature-agent": {agent_header}\n'
            f'"@signature-params": {params}').encode()
    signature = base64.b64encode(private_key.sign(base)).decode()
    return {
        "Signature-Agent": agent_header,
        "Signature-Input": f"sig1={params}",
        "Signature": f"sig1=:{signature}:",
    }
