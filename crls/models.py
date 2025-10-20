# crls/models.py
from django.db import models
from django.utils.text import slugify
from django.utils import timezone
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver

# Expiry helpers
from datetime import timezone as dt_timezone
from cryptography import x509  # used to parse certificate files


class CA(models.Model):
    name = models.CharField(max_length=200, unique=True)
    slug = models.SlugField(max_length=200, unique=True, blank=True)
    active = models.BooleanField(default=True)

    # Public distribution of issuer (single PEM or a bundle)
    issuer_cert_pem = models.FileField(upload_to="pki/", blank=True, null=True)

    # Optional stored CA material (already used by your CA creator)
    cert_pem = models.TextField(blank=True, default="")
    key_pem = models.TextField(blank=True, default="")
    next_serial = models.BigIntegerField(default=1)

    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.name)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name

    def latest_crl(self):
        return self.crls.order_by("-uploaded_at", "-id").first()

    # NEW: expiry of the CA certificate (UTC, aware) – read from cert_pem text
    @property
    def expires_at(self):
        """
        Datetime (aware, UTC) when this CA certificate expires, or None if not parseable.
        Reads CA.cert_pem (text). If it's empty, tries issuer_cert_pem file as a fallback.
        """
        # Prefer the CA's own text PEM (cert_pem). If empty, try issuer file.
        raw = None
        if self.cert_pem:
            raw = self.cert_pem.encode("utf-8")
        elif self.issuer_cert_pem:
            try:
                with self.issuer_cert_pem.open("rb") as fh:
                    raw = fh.read()
            except Exception:
                raw = None
        if not raw:
            return None

        b = raw.lstrip()
        cert = None

        # Try PEM (single)
        if b.startswith(b"-----BEGIN"):
            try:
                cert = x509.load_pem_x509_certificate(b)
            except Exception:
                # Try to find the first explicit CERT block in a bundle
                for chunk in b.split(b"-----END CERTIFICATE-----"):
                    if b"-----BEGIN CERTIFICATE-----" in chunk:
                        blob = chunk + b"-----END CERTIFICATE-----\n"
                        try:
                            cert = x509.load_pem_x509_certificate(blob)
                            break
                        except Exception:
                            continue
        else:
            # Try DER
            try:
                cert = x509.load_der_x509_certificate(b)
            except Exception:
                pass

        if cert is None:
            return None

        try:
            dt = cert.not_valid_after_utc  # cryptography >= 41
        except Exception:
            dt = cert.not_valid_after

        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=dt_timezone.utc)
        return dt


class CRL(models.Model):
    SOURCE_CHOICES = (
        ("manual", "Manual upload"),
        ("opnsense", "OPNsense"),
        ("http", "HTTP/HTTPS"),
    )

    ca = models.ForeignKey(CA, on_delete=models.CASCADE, related_name="crls")
    uploaded_at = models.DateTimeField(auto_now_add=True)
    source = models.CharField(max_length=16, choices=SOURCE_CHOICES, default="manual")

    # Parsed metadata
    last_update = models.DateTimeField(null=True, blank=True)
    next_update = models.DateTimeField(null=True, blank=True)
    revoked_count = models.PositiveIntegerField(default=0)
    sha256 = models.CharField(max_length=64, blank=True, default="")

    # Files (we keep original; also normalized DER/PEM)
    original_file = models.FileField(upload_to="crl/original/")
    der_file = models.FileField(upload_to="crl/der/", blank=True, null=True)
    pem_file = models.FileField(upload_to="crl/pem/", blank=True, null=True)

    def __str__(self):
        return f"{self.ca.name} CRL @ {self.uploaded_at:%Y-%m-%d %H:%M:%S}"


class OpnsenseSource(models.Model):
    AUTH_CHOICES = (("key", "SSH key"), ("password", "Password"))
    ca = models.OneToOneField(CA, on_delete=models.CASCADE, related_name="opnsense_source")

    enabled = models.BooleanField(default=False)
    host = models.CharField(max_length=255)
    port = models.PositiveIntegerField(default=22)
    username = models.CharField(max_length=128)
    auth_method = models.CharField(max_length=16, choices=AUTH_CHOICES, default="key")
    ssh_key_path = models.CharField(max_length=512, blank=True, default="")
    password = models.CharField(max_length=256, blank=True, default="")
    remote_path = models.CharField(max_length=512, help_text="Remote file path to the CRL")

    last_sync = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"OPNsense({self.host}) for {self.ca.name}"


class HttpSource(models.Model):
    AUTH_CHOICES = (("none", "None"), ("basic", "HTTP Basic"), ("header", "Custom header"))
    ca = models.OneToOneField(CA, on_delete=models.CASCADE, related_name="http_source")

    enabled = models.BooleanField(default=False)
    url = models.URLField()
    verify_tls = models.BooleanField(default=True)

    auth_method = models.CharField(max_length=16, choices=AUTH_CHOICES, default="none")
    username = models.CharField(max_length=128, blank=True, default="")
    password = models.CharField(max_length=256, blank=True, default="")
    header_name = models.CharField(max_length=128, blank=True, default="")
    header_value = models.CharField(max_length=256, blank=True, default="")

    timeout_seconds = models.PositiveIntegerField(default=20)

    last_sync = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"HTTP({self.url}) for {self.ca.name}"


class IssuedCert(models.Model):
    """
    Issued certificate record. cert_pem should contain the certificate (PEM or DER).
    key_pem/p12_file are optional.
    """
    ca = models.ForeignKey(CA, on_delete=models.CASCADE, related_name="issued")
    cert_pem = models.FileField(upload_to="issued/")
    key_pem = models.FileField(upload_to="issued/", blank=True, null=True)
    p12_file = models.FileField(upload_to="issued/", blank=True, null=True)

    # Auto-filled fields
    subject_cn = models.CharField(max_length=255, blank=True, default="")
    serial_hex = models.CharField(max_length=256, blank=True, default="")
    serial_decimal = models.CharField(max_length=256, blank=True, default="")
    uploaded_at = models.DateTimeField(auto_now_add=True)

    # Local mirrors for admin UX
    revoked = models.BooleanField(default=False)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoke_reason = models.CharField(max_length=64, blank=True, default="")

    # Convenience flags for templates
    @property
    def has_key(self) -> bool:
        return bool(self.key_pem)

    @property
    def has_p12(self) -> bool:
        return bool(self.p12_file)

    # Expiry timestamp parsed from cert_pem (timezone-aware UTC)
    @property
    def expires_at(self):
        """
        Datetime (aware, UTC) when this certificate expires, or None if not parseable/missing.
        Accepts PEM, DER, or PEM bundles with extra blocks (grabs first CERT block).
        """
        try:
            if not self.cert_pem:
                return None
            with self.cert_pem.open("rb") as fh:
                raw = fh.read()

            cert = None
            b = (raw or b"").lstrip()

            # Try PEM (single)
            if b.startswith(b"-----BEGIN"):
                try:
                    cert = x509.load_pem_x509_certificate(b)
                except Exception:
                    # Try to find the first explicit CERT block in a bundle (handles cert+key uploads)
                    for chunk in b.split(b"-----END CERTIFICATE-----"):
                        if b"-----BEGIN CERTIFICATE-----" in chunk:
                            blob = chunk + b"-----END CERTIFICATE-----\n"
                            try:
                                cert = x509.load_pem_x509_certificate(blob)
                                break
                            except Exception:
                                continue
            else:
                # Try DER
                try:
                    cert = x509.load_der_x509_certificate(b)
                except Exception:
                    pass

            if cert is None:
                return None

            # cryptography >= 41: not_valid_after_utc; fallback otherwise
            try:
                dt = cert.not_valid_after_utc
            except Exception:
                dt = cert.not_valid_after

            if dt is None:
                return None
            # normalize to aware UTC
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=dt_timezone.utc)
            return dt
        except Exception:
            return None

    @property
    def is_expired(self) -> bool:
        ea = self.expires_at
        return bool(ea and ea <= timezone.now())

    def __str__(self):
        label = self.subject_cn or self.serial_hex or "issued cert"
        return f"{self.ca.name}: {label}"


class OcspSigner(models.Model):
    ca = models.OneToOneField(CA, on_delete=models.CASCADE, related_name="ocsp_signer")
    enabled = models.BooleanField(default=False)

    signer_cert_pem = models.FileField(upload_to="ocsp/")
    signer_key_pem = models.FileField(upload_to="ocsp/")
    signer_key_password = models.CharField(max_length=256, blank=True, default="")

    include_signer_in_response = models.BooleanField(default=True)
    strict_unknown = models.BooleanField(
        default=False,
        help_text="If enabled, return UNKNOWN when a serial is not present in IssuedCerts.",
    )
    next_update_seconds = models.PositiveIntegerField(default=3600)

    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"OCSP Signer for {self.ca.name}"


class RevokedCert(models.Model):
    ca = models.ForeignKey(CA, on_delete=models.CASCADE, related_name="local_revoked")
    serial_decimal = models.CharField(max_length=256)
    reason = models.CharField(max_length=100, blank=True, default="")
    revoked_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = (("ca", "serial_decimal"),)

    def __str__(self):
        return f"Revoked {self.serial_decimal} @ {self.ca.name}"


@receiver(post_save, sender=RevokedCert)
def _mirror_revoked_to_issued(sender, instance: "RevokedCert", **kwargs):
    IssuedCert.objects.filter(
        ca=instance.ca, serial_decimal=instance.serial_decimal
    ).update(
        revoked=True,
        revoked_at=instance.revoked_at or timezone.now(),
        revoke_reason=instance.reason or "",
    )


@receiver(post_delete, sender=RevokedCert)
def _unmirror_revoked_to_issued(sender, instance: "RevokedCert", **kwargs):
    IssuedCert.objects.filter(
        ca=instance.ca, serial_decimal=instance.serial_decimal
    ).update(
        revoked=False,
        revoked_at=None,
        revoke_reason="",
    )
