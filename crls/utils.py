# crls/utils.py
import base64
import hashlib
from functools import lru_cache
from datetime import datetime, timedelta, timezone as dt_timezone
from django.core.files.base import ContentFile
from django.utils import timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    load_pem_private_key,
)
from cryptography.x509.oid import ExtensionOID, NameOID, AuthorityInformationAccessOID
from cryptography.x509 import ocsp as ocsp_mod

import paramiko
from paramiko import Ed25519Key, RSAKey, ECDSAKey
import requests

# ------------------------------------------------------------
# Sentinel: "this request does not belong to this CA"
# ------------------------------------------------------------
class OcspNoMatch(Exception):
    """Signal that the OCSP request does not belong to this CA (try next CA)."""
    pass

# -------------------------------------------------------------------
# Cert parsing helpers (CN + serials)
# -------------------------------------------------------------------

def parse_cert_pem_to_parts(raw: bytes):
    """
    Return (subject_cn, serial_hex, serial_decimal) from a single end-entity certificate.
    Accepts PEM, DER, or a PEM bundle (we take the first CERT block).
    """
    b = (raw or b"").lstrip()
    cert = None

    if b.startswith(b"-----BEGIN"):
        # single PEM try
        try:
            cert = x509.load_pem_x509_certificate(b)
        except Exception:
            # find first cert block from a bundle
            for chunk in b.split(b"-----END CERTIFICATE-----"):
                if b"-----BEGIN CERTIFICATE-----" in chunk:
                    blob = chunk + b"-----END CERTIFICATE-----\n"
                    try:
                        cert = x509.load_pem_x509_certificate(blob)
                        break
                    except Exception:
                        continue
    else:
        try:
            cert = x509.load_der_x509_certificate(b)
        except Exception:
            pass

    if cert is None:
        raise ValueError("Could not parse certificate (PEM/DER expected).")

    try:
        attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        subject_cn = attrs[0].value if attrs else ""
    except Exception:
        subject_cn = ""

    sn = cert.serial_number
    serial_decimal = str(int(sn))
    serial_hex = format(sn, "X")

    return subject_cn, serial_hex, serial_decimal


# -------------------------------------------------------------------
# Time helpers
# -------------------------------------------------------------------

def _to_utc_safe(dt):
    """Return a timezone-aware (UTC) datetime or None; guard against invalid years."""
    if dt is None:
        return None
    try:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=dt_timezone.utc)
        else:
            dt = dt.astimezone(dt_timezone.utc)
        if not (1 <= dt.year <= 9999):
            return None
        return dt
    except Exception:
        return None


def _get_dt_utc(obj, utc_attr: str, legacy_attr: str):
    """Prefer cryptography's *_utc attributes; fall back to legacy names; normalize to UTC."""
    try:
        dt = getattr(obj, utc_attr)
        if dt is not None:
            return dt
    except Exception:
        pass
    return _to_utc_safe(getattr(obj, legacy_attr, None))


def _normalize_next_update(dt):
    """Treat extreme 'infinite' nextUpdate (year >= 9999) as None; else UTC."""
    try:
        if dt and dt.year >= 9999:
            return None
    except Exception:
        return None
    return _to_utc_safe(dt)


# -------------------------------------------------------------------
# CRL parsing & normalization
# -------------------------------------------------------------------

def _revoked_count_safe(crl_obj) -> int:
    """Return number of revoked certs across cryptography versions without AttributeErrors."""
    try:
        rc = crl_obj.revoked_certificates
        if rc is None:
            return 0
        try:
            return len(rc)
        except TypeError:
            return sum(1 for _ in rc)
    except AttributeError:
        try:
            return sum(1 for _ in crl_obj)  # Rust backend: CRL iterable
        except TypeError:
            return 0


def parse_and_normalize_crl(crl_model, raw_bytes: bytes):
    """
    Parse CRL bytes (PEM or DER). If not a CRL, raise ValueError.
    On success, populate metadata and attach normalized DER/PEM files
    to the CRL model instance (without saving it).
    """
    if not raw_bytes:
        raise ValueError("Empty file uploaded.")

    data = raw_bytes.lstrip()

    # Detect PEM vs DER and CERT vs CRL explicitly
    if data.startswith(b"-----BEGIN "):
        if b"-----BEGIN X509 CRL-----" in data:
            try:
                parsed = x509.load_pem_x509_crl(data)
            except Exception as e:
                raise ValueError(f"Failed to parse PEM CRL: {e}")
        elif b"-----BEGIN CERTIFICATE-----" in data:
            raise ValueError("This file is a PEM X.509 certificate, not a CRL.")
        else:
            raise ValueError("Unrecognized PEM header. Expected '-----BEGIN X509 CRL-----'.")
    else:
        try:
            parsed = x509.load_der_x509_crl(data)
        except Exception:
            # Maybe it's a DER certificate
            try:
                x509.load_der_x509_certificate(data)
                raise ValueError("This file is a DER X.509 certificate, not a CRL.")
            except Exception:
                raise ValueError("Unrecognized binary format. Expected a CRL in DER or PEM.")

    if not isinstance(parsed, x509.CertificateRevocationList):
        raise ValueError(f"Parsed object is not a CRL (got {type(parsed)}).")

    der_bytes = parsed.public_bytes(Encoding.DER)
    pem_bytes = parsed.public_bytes(Encoding.PEM)

    crl_model.last_update = _get_dt_utc(parsed, "last_update_utc", "last_update")
    crl_model.next_update = _normalize_next_update(
        _get_dt_utc(parsed, "next_update_utc", "next_update")
    )
    crl_model.revoked_count = _revoked_count_safe(parsed)
    crl_model.sha256 = hashlib.sha256(der_bytes).hexdigest()

    ts = int(timezone.now().timestamp())
    crl_model.der_file.save(f"{crl_model.ca.slug}-{ts}.crl", ContentFile(der_bytes), save=False)
    crl_model.pem_file.save(f"{crl_model.ca.slug}-{ts}.pem", ContentFile(pem_bytes), save=False)


# -------------------------------------------------------------------
# Fetchers (OPNsense via SFTP, and HTTP/HTTPS)
# -------------------------------------------------------------------

def _load_pkey(path: str):
    """Support RSA/ECDSA/Ed25519 private keys for SSH key auth."""
    for keycls in (Ed25519Key, RSAKey, ECDSAKey):
        try:
            return keycls.from_private_key_file(path)
        except Exception:
            continue
    raise ValueError(f"Unsupported or unreadable SSH key at {path}")


def fetch_from_opnsense(source) -> bytes:
    """
    Fetch a remote CRL file via SFTP from OPNsense.
    Supports SSH key or password based on source.auth_method.
    """
    transport = paramiko.Transport((source.host, source.port))
    if getattr(source, "auth_method", "key") == 'password':
        transport.connect(username=source.username, password=source.password)
    else:
        pkey = _load_pkey(source.ssh_key_path)
        transport.connect(username=source.username, pkey=pkey)

    sftp = paramiko.SFTPClient.from_transport(transport)
    try:
        with sftp.open(source.remote_path, 'rb') as f:
            return f.read()
    finally:
        sftp.close()
        transport.close()


def fetch_from_http(http_source) -> bytes:
    """
    Fetch a CRL over HTTP/HTTPS.
    Supports: no auth, Basic auth, or custom header (e.g., Bearer token).
    """
    headers = {}
    auth = None

    if http_source.auth_method == 'basic':
        auth = (http_source.username, http_source.password)
    elif http_source.auth_method == 'header':
        if http_source.header_name and http_source.header_value:
            headers[http_source.header_name] = http_source.header_value

    verify = http_source.verify_tls
    try:
        resp = requests.get(
            http_source.url,
            headers=headers,
            auth=auth,
            timeout=http_source.timeout_seconds or 20,
            verify=verify,
        )
    except Exception as e:
        raise ValueError(f"HTTP fetch failed: {e}")

    if resp.status_code != 200:
        raise ValueError(f"HTTP fetch failed with status {resp.status_code}")

    content = resp.content or b""
    sniff = content[:64].lstrip()
    ct = (resp.headers.get("Content-Type") or "").lower()

    if "text/html" in ct or sniff.startswith(b"<!doctype") or sniff.startswith(b"<html"):
        raise ValueError("Server returned HTML (likely a login page), not a CRL file.")

    if not content:
        raise ValueError("HTTP fetch returned empty body")

    return content


# -------------------------------------------------------------------
# OCSP helpers
# -------------------------------------------------------------------

def _iter_revoked(crl):
    """Robustly iterate revoked cert entries across cryptography versions."""
    try:
        rc = crl.revoked_certificates
        if rc is None:
            return []
        try:
            return list(rc)
        except TypeError:
            return [r for r in rc]
    except AttributeError:
        try:
            return list(crl)  # Rust backend: CRL itself is iterable
        except TypeError:
            return []


@lru_cache(maxsize=64)
def _parse_revoked_map(der_or_pem_bytes: bytes):
    """
    Return (revoked_map, last_update, next_update).
    revoked_map = { int(serial): (revocation_time_utc, reason_or_None) }
    """
    data = der_or_pem_bytes.lstrip()
    crl = x509.load_pem_x509_crl(data) if data.startswith(b"-----BEGIN") else x509.load_der_x509_crl(data)

    revoked_map = {}
    for r in _iter_revoked(crl):
        # revocation time (prefer *_utc)
        try:
            rev_dt = r.revocation_date_utc
        except Exception:
            rev_dt = _to_utc_safe(getattr(r, "revocation_date", None))

        reason = None
        try:
            ext = r.extensions.get_extension_for_oid(ExtensionOID.CRL_REASON)
            reason = ext.value.reason
        except Exception:
            pass

        revoked_map[int(r.serial_number)] = (rev_dt, reason)

    last_u = _get_dt_utc(crl, "last_update_utc", "last_update")
    next_u = _normalize_next_update(_get_dt_utc(crl, "next_update_utc", "next_update"))
    return revoked_map, last_u, next_u


def latest_crl_bytes_for_ca(ca):
    """
    Return (bytes, last_update, next_update, revoked_map) for the CA's latest CRL.
    """
    crl = ca.latest_crl()
    if not crl:
        return None, None, None, {}
    if crl.der_file:
        data = crl.der_file.open('rb').read()
    elif crl.pem_file:
        data = crl.pem_file.open('rb').read()
    else:
        data = crl.original_file.open('rb').read()
    revoked_map, last_u, next_u = _parse_revoked_map(data)
    return data, last_u, next_u, revoked_map


def _load_cert_from_filefield(ff) -> x509.Certificate:
    return x509.load_pem_x509_certificate(ff.open('rb').read())


def _load_key_from_filefield(ff, password: str):
    pw = password.encode() if password else None
    return load_pem_private_key(ff.open('rb').read(), password=pw)


def _b64url_decode(s: str) -> bytes:
    """base64url without padding as in RFC 6960 GET; add padding back."""
    pad = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _load_issuer_for_leaf(issuer_ff, ee_cert: x509.Certificate) -> x509.Certificate:
    """
    Load the correct issuer certificate from a FileField that might contain
    a single PEM, a PEM *bundle*, or DER. Prefer the one whose Subject == ee_cert.issuer.
    """
    data = issuer_ff.open('rb').read()

    # Try a single PEM
    try:
        return x509.load_pem_x509_certificate(data)
    except Exception:
        pass

    # Try DER
    try:
        return x509.load_der_x509_certificate(data)
    except Exception:
        pass

    # Try a PEM bundle: split and parse each block
    certs = []
    for chunk in data.split(b"-----END CERTIFICATE-----"):
        if b"-----BEGIN CERTIFICATE-----" in chunk:
            blob = chunk + b"-----END CERTIFICATE-----\n"
            try:
                certs.append(x509.load_pem_x509_certificate(blob))
            except Exception:
                continue

    # Prefer the one whose Subject matches the leaf's Issuer
    for c in certs:
        if c.subject == ee_cert.issuer:
            return c

    if certs:
        return certs[0]

    raise ValueError("Issuer certificate file is not a valid PEM/DER or bundle.")

# --- robust issuer-bytes loader for self-signed CAs or missing issuer file ---
def _get_issuer_cert_bytes_for_ca(ca):
    """
    Prefer issuer_cert_pem FileField if it exists and is non-empty; otherwise
    fall back to ca.cert_pem (self-signed case). Return raw bytes (PEM or DER).
    """
    f = getattr(ca, "issuer_cert_pem", None)
    if f:
        try:
            with f.open("rb") as fh:
                data = fh.read()
                if data and data.strip():
                    return data
        except Exception:
            pass

    txt = getattr(ca, "cert_pem", None)
    if txt:
        data = txt.encode("utf-8")
        if data and data.strip():
            return data

    raise ValueError("No issuer certificate material found for CA.")

def build_ocsp_response_bytes(ca, signer, req_der: bytes) -> bytes:
    """
    Build a single-response OCSPResponse for the given CA using the latest CRL.
    Requires:
      - issuer certificate (either ca.issuer_cert_pem or ca.cert_pem for self-signed)
      - OcspSigner (cert+key)
      - The leaf certificate present in IssuedCerts for the requested serial
    Returns DER-encoded OCSPResponse bytes.
    """
    req = ocsp_mod.load_der_ocsp_request(req_der)
    serial = getattr(req, "serial_number", None)
    if serial is None:
        return ocsp_mod.OCSPResponseBuilder().build_unsuccessful(
            ocsp_mod.OCSPResponseStatus.MALFORMED_REQUEST
        ).public_bytes(Encoding.DER)

    from .models import IssuedCert  # lazy import to avoid cycles
    ic = IssuedCert.objects.filter(ca=ca, serial_decimal=str(serial)).first()
    if not ic:
        # Not for this CA — let the caller try the next CA
        raise OcspNoMatch()

    ee_cert = x509.load_pem_x509_certificate(ic.cert_pem.open('rb').read())

    # Robust issuer selection
    issuer_cert = None
    # 1) If a file-backed issuer is present, use bundle-aware loader (best match)
    if getattr(ca, "issuer_cert_pem", None):
        try:
            issuer_cert = _load_issuer_for_leaf(ca.issuer_cert_pem, ee_cert)
        except Exception:
            issuer_cert = None

    # 2) Fallback to the CA's own cert_pem (self-signed case)
    if issuer_cert is None and getattr(ca, "cert_pem", None):
        try:
            issuer_cert = x509.load_pem_x509_certificate(ca.cert_pem.encode("utf-8"))
        except Exception:
            issuer_cert = None

    # 3) Final fallback: generic loader from either source (PEM/DER)
    if issuer_cert is None:
        try:
            blob = _get_issuer_cert_bytes_for_ca(ca)
            try:
                issuer_cert = x509.load_pem_x509_certificate(blob)
            except ValueError:
                issuer_cert = x509.load_der_x509_certificate(blob)
        except Exception:
            issuer_cert = None

    if issuer_cert is None:
        # Can't compute a matching CertID with this CA — try next CA
        raise OcspNoMatch()

    _, _, crl_next, revoked_map = latest_crl_bytes_for_ca(ca)
    now = timezone.now()
    this_update = now
    next_update = crl_next or (now + timedelta(seconds=signer.next_update_seconds))

    status = ocsp_mod.OCSPCertStatus.GOOD
    rev_time = None
    rev_reason = None

    if serial in revoked_map:
        rev_time, rev_reason = revoked_map[serial]
        status = ocsp_mod.OCSPCertStatus.REVOKED
    else:
        if getattr(signer, "strict_unknown", False):
            present = IssuedCert.objects.filter(ca=ca, serial_decimal=str(serial)).exists()
            if not present:
                status = ocsp_mod.OCSPCertStatus.UNKNOWN

    algo = getattr(req, "hash_algorithm", None) or hashes.SHA256()
    builder = ocsp_mod.OCSPResponseBuilder().add_response(
        cert=ee_cert,
        issuer=issuer_cert,
        algorithm=algo,
        cert_status=status,
        this_update=this_update,
        next_update=next_update,
        revocation_time=rev_time,
        revocation_reason=rev_reason,
    )

    try:
        ext = req.extensions.get_extension_for_oid(ExtensionOID.OCSP_NONCE)
        builder = builder.add_extension(ext.value, critical=False)
    except Exception:
        pass

    signer_cert = _load_cert_from_filefield(signer.signer_cert_pem)
    signer_key = _load_key_from_filefield(signer.signer_key_pem, getattr(signer, "signer_key_password", ""))

    builder = builder.responder_id(ocsp_mod.OCSPResponderEncoding.NAME, signer_cert)
    if getattr(signer, "include_signer_in_response", True):
        builder = builder.certificates([signer_cert])

    response = builder.sign(private_key=signer_key, algorithm=hashes.SHA256())
    return response.public_bytes(Encoding.DER)


# -------------------------------------------------------------------
# CA helpers (single canonical block)
# -------------------------------------------------------------------

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates

def _hash_by_name(name: str):
    name = (name or "").upper().replace("-", "")
    return {
        "SHA256": hashes.SHA256(),
        "SHA384": hashes.SHA384(),
        "SHA512": hashes.SHA512(),
    }.get(name, hashes.SHA256())

def generate_private_key(key_type: str = "RSA-2048"):
    kt = (key_type or "").upper()
    if kt.startswith("RSA"):
        bits = 2048
        if "4096" in kt:
            bits = 4096
        return rsa.generate_private_key(public_exponent=65537, key_size=bits)
    # EC curve
    if "P256" in kt:
        curve = ec.SECP256R1()
    elif "P384" in kt:
        curve = ec.SECP384R1()
    else:
        curve = ec.SECP256R1()
    return ec.generate_private_key(curve)

def private_key_to_pem(key) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

def load_private_key_pem(pem: bytes, password: bytes | None = None):
    return serialization.load_pem_private_key(pem, password=password)

def certificate_to_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)

def load_certificate_pem(pem: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem)

def build_subject(
    *,
    common_name: str,
    country: str | None = None,
    state: str | None = None,
    city: str | None = None,
    organization: str | None = None,
    organizational_unit: str | None = None,
    email: str | None = None,
) -> x509.Name:
    parts = []
    if country:
        parts.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
    if state:
        parts.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
    if city:
        parts.append(x509.NameAttribute(NameOID.LOCALITY_NAME, city))
    if organization:
        parts.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
    if organizational_unit:
        parts.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit))
    if email:
        parts.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))
    if common_name:
        parts.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
    return x509.Name(parts)

def create_ca_certificate(
    subject_key,
    subject_name: x509.Name,
    *,
    issuer_key=None,
    issuer_name: x509.Name | None = None,
    lifetime_days: int = 825,
    digest_name: str = "SHA256",
    is_ca: bool = True,
) -> x509.Certificate:
    issuer_key = issuer_key or subject_key
    issuer_name = issuer_name or subject_name
    now = timezone.now().astimezone(dt_timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=int(lifetime_days)))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            key_cert_sign=True,
            crl_sign=True,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ), critical=True)
    )
    return builder.sign(private_key=issuer_key, algorithm=_hash_by_name(digest_name))

def to_pkcs12_bytes(friendly_name: str, key, cert: x509.Certificate, cas: list[x509.Certificate] | None = None) -> bytes:
    return serialize_key_and_certificates(
        name=(friendly_name or "").encode("utf-8"),
        key=key,
        cert=cert,
        cas=cas or None,
        encryption_algorithm=serialization.NoEncryption(),
    )

def generate_internal_ca_pem(
    *,
    common_name: str,
    country_code: str = "",
    state: str = "",
    city: str = "",
    organization: str = "",
    organizational_unit: str = "",
    email: str = "",
    ocsp_uri: str = "",
    key_type: str = "rsa2048",
    digest_algo: str = "sha256",
    lifetime_days: int = 825,
    parent_ca=None,  # optional CA instance with cert/key available when signing
):
    """
    Create a self-signed CA by default, or a CA signed by 'parent_ca' (if provided).
    Returns (cert_pem_str, key_pem_str).
    """
    # Normalize key_type for helper
    kt = (key_type or "").upper().replace("_", "").replace(" ", "").replace("-", "")
    if kt in ("RSA", "RSA2048"):
        norm_key_type = "RSA-2048"
    elif kt in ("RSA4096",):
        norm_key_type = "RSA-4096"
    elif kt in ("ECP256", "P256", "EC256"):
        norm_key_type = "EC-P256"
    elif kt in ("ECP384", "P384", "EC384"):
        norm_key_type = "EC-P384"
    else:
        norm_key_type = "RSA-2048"

    # Subject/key for the new CA
    priv_key = generate_private_key(norm_key_type)
    subject = build_subject(
        common_name=common_name,
        country=country_code,
        state=state,
        city=city,
        organization=organization,
        organizational_unit=organizational_unit,
        email=email,
    )

    issuer_key = priv_key
    issuer_name = subject
    issuer_pub_for_aki = priv_key.public_key()

    # If a parent CA was chosen, use its key+cert to sign
    if parent_ca:
        parent_key_pem = getattr(parent_ca, "key_pem", "") or ""
        if not parent_key_pem:
            raise ValueError("Selected signing CA has no private key stored.")

        from cryptography.hazmat.primitives import serialization as _ser
        issuer_key = _ser.load_pem_private_key(parent_key_pem.encode(), password=None)
        issuer_pub_for_aki = issuer_key.public_key()

        # Parent cert: prefer text field cert_pem if present; otherwise use file field issuer_cert_pem
        parent_cert = None
        parent_cert_pem = getattr(parent_ca, "cert_pem", "") or ""
        if parent_cert_pem:
            parent_cert = x509.load_pem_x509_certificate(parent_cert_pem.encode())
        elif getattr(parent_ca, "issuer_cert_pem", None):
            with parent_ca.issuer_cert_pem.open("rb") as f:
                parent_cert = x509.load_pem_x509_certificate(f.read())

        if not parent_cert:
            raise ValueError("Selected signing CA has no certificate material.")
        issuer_name = parent_cert.subject

    # Build certificate (CA=true) with optional OCSP AIA
    now = timezone.now().astimezone(dt_timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(priv_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=int(lifetime_days or 825)))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(priv_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_pub_for_aki), critical=False)
    )

    if ocsp_uri:
        builder = builder.add_extension(
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        AuthorityInformationAccessOID.OCSP,
                        x509.UniformResourceIdentifier(ocsp_uri),
                    )
                ]
            ),
            critical=False,
        )

    cert = builder.sign(private_key=issuer_key, algorithm=_hash_by_name(digest_algo))
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    key_pem = private_key_to_pem(priv_key).decode("utf-8")
    return cert_pem, key_pem



# === Leaf issuance helpers (server/client) ===
from ipaddress import ip_address
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, AuthorityInformationAccessOID

def build_subject2(
    *,
    common_name: str,
    country_code: str = "",
    state: str = "",
    city: str = "",
    organization: str = "",
    organizational_unit: str = "",
    email: str = "",
) -> x509.Name:
    """Thin wrapper that calls build_subject with the field names used in forms/views."""
    return build_subject(
        common_name=common_name,
        country=country_code,
        state=state,
        city=city,
        organization=organization,
        organizational_unit=organizational_unit,
        email=email,
    )

def _normalize_leaf_key_type(s: str | None) -> str:
    """Map form choices to generate_private_key() choices."""
    s = (s or "").upper().replace(" ", "").replace("_", "").replace("-", "")
    if s in ("RSA", "RSA2048"):
        return "RSA-2048"
    if s in ("RSA4096",):
        return "RSA-4096"
    if s in ("ECP256", "P256", "EC256"):
        return "EC-P256"
    if s in ("ECP384", "P384", "EC384"):
        return "EC-P384"
    return "RSA-2048"

def _load_ca_signing_material(ca):
    """
    Load issuer_name and private key from CA.
    Prefers text fields (cert_pem/key_pem), falls back to issuer_cert_pem file for the cert.
    """
    # --- private key (required) ---
    key_pem = getattr(ca, "key_pem", "") or ""
    if not key_pem:
        raise ValueError(f"CA '{ca}' has no private key stored (key_pem).")
    signer_key = serialization.load_pem_private_key(key_pem.encode("utf-8"), password=None)

    # --- certificate (issuer_name) ---
    issuer_cert = None
    txt_cert = getattr(ca, "cert_pem", "") or ""
    if txt_cert:
        issuer_cert = x509.load_pem_x509_certificate(txt_cert.encode("utf-8"))
    elif getattr(ca, "issuer_cert_pem", None):
        # issuer_cert_pem may be a single PEM, a bundle, or DER
        raw = ca.issuer_cert_pem.open("rb").read()
        if raw.lstrip().startswith(b"-----BEGIN"):
            # try single pem
            try:
                issuer_cert = x509.load_pem_x509_certificate(raw)
            except Exception:
                # try first block of a bundle
                for chunk in raw.split(b"-----END CERTIFICATE-----"):
                    if b"-----BEGIN CERTIFICATE-----" in chunk:
                        blob = chunk + b"-----END CERTIFICATE-----\n"
                        try:
                            issuer_cert = x509.load_pem_x509_certificate(blob)
                            break
                        except Exception:
                            continue
        else:
            try:
                issuer_cert = x509.load_der_x509_certificate(raw)
            except Exception:
                pass

    if not issuer_cert:
        raise ValueError(f"CA '{ca}' has no certificate material (cert_pem/issuer_cert_pem).")

    return issuer_cert.subject, issuer_cert.public_key(), signer_key

def create_leaf_signed_by_ca(
    *,
    ca,
    subject: x509.Name,
    cert_type: str = "client",          # "client" or "server"
    key_type: str = "RSA-2048",
    digest_algo: str = "SHA256",
    lifetime_days: int = 397,
    dns_names: list[str] | None = None,
    ip_addrs: list[str] | None = None,
    ocsp_uri: str | None = None,
) -> tuple[str, str]:
    """
    Issue a leaf (end-entity) certificate signed by the given CA.
    Returns (cert_pem_str, key_pem_str). The private key is returned to caller; it is NOT stored.
    Requires CA.key_pem and (CA.cert_pem or CA.issuer_cert_pem).
    """
    # Generate leaf key
    key = generate_private_key(_normalize_leaf_key_type(key_type))

    # Serial number (uses CA.next_serial if present, else random)
    try:
        sn = int(getattr(ca, "next_serial", 0) or 0)
    except Exception:
        sn = 0
    if sn <= 0:
        serial_number = x509.random_serial_number()
        use_next_serial = False
    else:
        serial_number = sn
        use_next_serial = True

    # Issuer info + signing key
    issuer_name, issuer_pub_for_aki, signer_key = _load_ca_signing_material(ca)

    now = datetime.now(dt_timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(serial_number)
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=int(lifetime_days or 397)))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_pub_for_aki), critical=False)
    )

    # EKU based on cert_type
    ekus = []
    t = (cert_type or "").lower()
    if "server" in t:
        ekus.append(ExtendedKeyUsageOID.SERVER_AUTH)
    if "client" in t:
        ekus.append(ExtendedKeyUsageOID.CLIENT_AUTH)
    if ekus:
        builder = builder.add_extension(x509.ExtendedKeyUsage(ekus), critical=False)

    # SANs
    san_items = []
    for d in dns_names or []:
        san_items.append(x509.DNSName(d))
    for ip in ip_addrs or []:
        san_items.append(x509.IPAddress(ip_address(ip)))
    if san_items:
        builder = builder.add_extension(x509.SubjectAlternativeName(san_items), critical=False)

    # AIA OCSP (optional)
    if ocsp_uri:
        builder = builder.add_extension(
            x509.AuthorityInformationAccess(
                [x509.AccessDescription(AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier(ocsp_uri))]
            ),
            critical=False,
        )

    cert = builder.sign(private_key=signer_key, algorithm=_hash_by_name(digest_algo))

    # If we consumed a sequential serial, bump it
    if use_next_serial:
        try:
            ca.next_serial = int(ca.next_serial) + 1
            ca.save(update_fields=["next_serial"])
        except Exception:
            pass

    cert_pem = certificate_to_pem(cert).decode("utf-8")
    key_pem = private_key_to_pem(key).decode("utf-8")
    return cert_pem, key_pem


def generate_crl_from_local_revokes(ca, *, next_update_seconds: int = 7 * 24 * 3600):
    """
    Build a CRL for `ca` using local revocations (RevokedCert records).
    Returns (der_bytes, pem_bytes, last_update, next_update, count).
    """
    from .models import RevokedCert  # <-- correct model name

    # We need issuer name and the signing key material on the CA record
    if not ca.cert_pem or not ca.key_pem:
        raise ValueError("CA must have cert_pem and key_pem to sign a CRL.")

    issuer_cert = x509.load_pem_x509_certificate(ca.cert_pem.encode("utf-8"))
    issuer_name = issuer_cert.subject
    sign_key = load_pem_private_key(ca.key_pem.encode("utf-8"), password=None)

    now = timezone.now()
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer_name)
        .last_update(now)
        .next_update(now + timedelta(seconds=next_update_seconds))
    )

    # Add every locally revoked serial for this CA
    count = 0
    qs = RevokedCert.objects.filter(ca=ca).only("serial_decimal", "revoked_at", "reason")
    for rec in qs:
        try:
            serial_int = int(rec.serial_decimal)
        except Exception:
            continue

        rev_dt = rec.revoked_at or now
        entry = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial_int)
            .revocation_date(rev_dt)
        )

        # Optional reason (maps your text -> x509.ReasonFlags if possible)
        if rec.reason:
            try:
                reason_flag = getattr(x509.ReasonFlags, rec.reason.lower(), None)
                if reason_flag is not None:
                    entry = entry.add_extension(x509.CRLReason(reason_flag), critical=False)
            except Exception:
                pass

        builder = builder.add_revoked_certificate(entry.build())
        count += 1

    crl = builder.sign(private_key=sign_key, algorithm=hashes.SHA256())
    der_bytes = crl.public_bytes(Encoding.DER)
    pem_bytes = crl.public_bytes(Encoding.PEM)

    return der_bytes, pem_bytes, now, now + timedelta(seconds=next_update_seconds), count
