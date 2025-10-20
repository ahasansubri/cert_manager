# crls/admin.py
from django.contrib import admin, messages
from django.core.files.base import ContentFile
from django.utils.html import format_html
from django.db.models import Exists, OuterRef
from django.utils import timezone

import hashlib
from datetime import timedelta, timezone as dt_timezone

from .utils import (
    generate_internal_ca_pem,
    parse_cert_pem_to_parts,
    to_pkcs12_bytes,
    generate_crl_from_local_revokes,
)

from .models import (
    CA,
    CRL,
    OpnsenseSource,
    HttpSource,
    IssuedCert,
    OcspSigner,
    RevokedCert,
)
from .forms import CAAdminForm

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID


# ---- simple cert parser for IssuedCert auto fields ----
def _parse_cert(fileobj):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    data = fileobj.read()
    try:
        cert = x509.load_pem_x509_certificate(data)
    except ValueError:
        cert = x509.load_der_x509_certificate(data)

    try:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception:
        cn = ""

    serial_int = cert.serial_number
    return cn, f"{serial_int:0X}", str(serial_int)


@admin.register(CA)
class CAAdmin(admin.ModelAdmin):
    form = CAAdminForm

    list_display = ("name", "slug", "active", "created_at")
    list_filter  = ("active",)
    search_fields = ("name", "slug", "description")
    readonly_fields = ("created_at",)

    fieldsets = (
        ("Identity", {"fields": ("name", "slug", "active")}),
        ("Creation / Import", {"fields": ("method",)}),
        # Internal CA options (virtual fields – all live on the form)
        ("Internal CA options", {
            "fields": (
                "issuer_mode", "issuer_parent",
                "key_type", "digest_algo", "lifetime_days",
                "common_name", "country_code", "state", "city",
                "organization", "organizational_unit", "email", "ocsp_uri",
            ),
            "description": "Shown only when Method = Create internal CA.",
        }),
        # Import / storage
        ("PEM storage (optional)", {
            "fields": ("issuer_cert_pem", "cert_pem", "key_pem", "cert_file", "key_file"),
            "description": (
                "For Import: you can paste PEM into the textareas or upload files. "
                "Issuer cert PEM helps complete the chain."
            ),
        }),
        ("Issuance control", {"fields": ("next_serial",)}),
        ("Timestamps", {"fields": ("created_at",)}),
    )

    def save_model(self, request, obj, form, change):
        """
        For internal method, generate cert/key if not already present.
        """
        method = form.cleaned_data.get("method")
        if method == CAAdminForm.METHOD_INTERNAL:
            try:
                parent = None
                if form.cleaned_data.get("issuer_mode") == "parent":
                    parent = form.cleaned_data.get("issuer_parent")

                if not obj.cert_pem or not obj.key_pem:
                    cert_pem, key_pem = generate_internal_ca_pem(
                        common_name=form.cleaned_data.get("common_name"),
                        country_code=form.cleaned_data.get("country_code") or "",
                        state=form.cleaned_data.get("state") or "",
                        city=form.cleaned_data.get("city") or "",
                        organization=form.cleaned_data.get("organization") or "",
                        organizational_unit=form.cleaned_data.get("organizational_unit") or "",
                        email=form.cleaned_data.get("email") or "",
                        ocsp_uri=form.cleaned_data.get("ocsp_uri") or "",
                        key_type=form.cleaned_data.get("key_type") or "rsa2048",
                        digest_algo=form.cleaned_data.get("digest_algo") or "sha256",
                        lifetime_days=form.cleaned_data.get("lifetime_days") or 825,
                        parent_ca=parent,
                    )
                    obj.cert_pem = cert_pem
                    obj.key_pem = key_pem
                    messages.success(request, "Internal CA material generated.")
            except Exception as e:
                messages.error(request, f"Internal CA generation failed: {e}")

        super().save_model(request, obj, form, change)


@admin.register(CRL)
class CRLAdmin(admin.ModelAdmin):
    list_display = ("ca", "source", "uploaded_at", "last_update", "next_update", "revoked_count", "sha256")
    list_filter = ("ca", "source")
    date_hierarchy = "uploaded_at"
    search_fields = ("ca__name", "sha256")
    readonly_fields = ("uploaded_at", "last_update", "next_update", "revoked_count", "sha256")


@admin.register(OpnsenseSource)
class OpnsenseSourceAdmin(admin.ModelAdmin):
    list_display = ("ca", "enabled", "host", "port", "username", "auth_method", "last_sync", "updated_at")
    list_filter = ("enabled", "auth_method")
    search_fields = ("host", "username")
    readonly_fields = ("last_sync", "updated_at")


@admin.register(HttpSource)
class HttpSourceAdmin(admin.ModelAdmin):
    list_display = ("ca", "enabled", "url", "verify_tls", "auth_method", "last_sync", "updated_at")
    list_filter = ("enabled", "auth_method", "verify_tls")
    search_fields = ("url",)
    readonly_fields = ("last_sync", "updated_at")


# ------------------------------
# OCSP Signer (auto-generate)
# ------------------------------
@admin.register(OcspSigner)
class OcspSignerAdmin(admin.ModelAdmin):
    """
    Admin that auto-creates an OCSP signer cert/key for the selected CA
    when saving (if they don't already exist). Upload fields are removed.
    """
    list_display = ("ca", "enabled", "include_signer_in_response", "strict_unknown", "next_update_seconds")
    list_filter = ("enabled", "strict_unknown", "ca")
    search_fields = ("ca__name",)
    # Show only the control fields; signer material handled automatically
    fields = ("ca", "enabled", "include_signer_in_response", "strict_unknown", "next_update_seconds")

    def save_model(self, request, obj, form, change):
        """
        If signer cert/key are missing, generate a new OCSP signer certificate
        and key signed by the selected CA.
        """
        # If we already have material, just save changes
        if obj.pk:
            existing = OcspSigner.objects.filter(pk=obj.pk).first()
        else:
            existing = None

        needs_material = True
        if existing and existing.signer_cert_pem and existing.signer_key_pem:
            needs_material = False
        if not existing and obj.signer_cert_pem and obj.signer_key_pem:
            needs_material = False

        if needs_material:
            try:
                ca = obj.ca
                # Load CA certificate (for issuer name & AKI)
                ca_cert = None
                if ca.cert_pem:
                    ca_cert = x509.load_pem_x509_certificate(ca.cert_pem.encode("utf-8"))
                elif ca.issuer_cert_pem:
                    with ca.issuer_cert_pem.open("rb") as fh:
                        blob = fh.read()
                    # try PEM first, then DER
                    try:
                        ca_cert = x509.load_pem_x509_certificate(blob)
                    except Exception:
                        ca_cert = x509.load_der_x509_certificate(blob)

                if not ca_cert:
                    raise ValueError("CA certificate material is required on the CA (cert_pem or issuer_cert_pem).")

                # Load CA private key
                if not ca.key_pem:
                    raise ValueError("CA private key (key_pem) is required on the CA to sign an OCSP responder.")
                ca_key = serialization.load_pem_private_key(ca.key_pem.encode("utf-8"), password=None)

                # Generate signer key (RSA 2048)
                signer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

                # Subject for OCSP signer
                subject = x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, f"OCSP Signer for {ca.name}")
                ])

                now = timezone.now().astimezone(dt_timezone.utc)
                builder = (
                    x509.CertificateBuilder()
                    .subject_name(subject)
                    .issuer_name(ca_cert.subject)
                    .public_key(signer_key.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(now - timedelta(minutes=5))
                    .not_valid_after(now + timedelta(days=365))  # 1 year
                    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                    .add_extension(
                        x509.KeyUsage(
                            digital_signature=True,
                            content_commitment=False,
                            key_encipherment=False,
                            data_encipherment=False,
                            key_agreement=False,
                            key_cert_sign=False,
                            crl_sign=False,
                            encipher_only=False,
                            decipher_only=False,
                        ),
                        critical=True,
                    )
                    .add_extension(
                        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]),
                        critical=False,
                    )
                    .add_extension(
                        x509.SubjectKeyIdentifier.from_public_key(signer_key.public_key()),
                        critical=False,
                    )
                )

                # Authority Key Identifier from CA public key
                try:
                    builder = builder.add_extension(
                        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
                        critical=False,
                    )
                except Exception:
                    # best-effort; not fatal
                    pass

                signer_cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

                # Save as PEM into model FileFields
                cert_pem = signer_cert.public_bytes(serialization.Encoding.PEM)
                key_pem  = signer_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )

                base = ca.slug or "ocsp"
                obj.signer_cert_pem.save(f"{base}-ocsp-signer.pem", ContentFile(cert_pem), save=False)
                obj.signer_key_pem.save(f"{base}-ocsp-signer.key.pem", ContentFile(key_pem), save=False)

                messages.success(request, "OCSP signer key and certificate were generated automatically.")
            except Exception as e:
                messages.error(request, f"Failed to generate OCSP signer: {e}")

        super().save_model(request, obj, form, change)


class RevokedYesNoFilter(admin.SimpleListFilter):
    title = "revoked"
    parameter_name = "revoked"

    def lookups(self, request, model_admin):
        return (("yes", "Yes"), ("no", "No"))

    def queryset(self, request, queryset):
        val = self.value()
        # Match by (ca, serial_decimal) so different CAs don't collide on serials
        revoked_exists = RevokedCert.objects.filter(
            ca=OuterRef("ca_id"),
            serial_decimal=OuterRef("serial_decimal"),
        )
        qs = queryset.annotate(_revoked=Exists(revoked_exists))
        if val == "yes":
            return qs.filter(_revoked=True)
        if val == "no":
            return qs.filter(_revoked=False)
        return qs


@admin.register(IssuedCert)
class IssuedCertAdmin(admin.ModelAdmin):
    list_display = (
        "ca",
        "subject_cn",
        "serial_hex",
        "serial_decimal",
        "uploaded_at",
        "revoked_local",       # computed from RevokedCert
        "revoked_at_local",    # computed display of time
    )
    list_filter = ("ca", RevokedYesNoFilter)
    search_fields = ("subject_cn", "serial_hex", "serial_decimal")
    date_hierarchy = "uploaded_at"
    exclude = ("subject_cn", "serial_hex", "serial_decimal", "p12_file")
    readonly_fields = ("uploaded_at",)

    fieldsets = (
        ("Certificate files", {"fields": ("ca", "cert_pem", "key_pem")}),
        ("Timestamps", {"fields": ("uploaded_at",)}),
        # REAL model fields here so admins can toggle and edit BEFORE revocation
        ("Revocation", {"fields": ("revoked", "revoked_at", "revoke_reason")}),
    )

    # status column (✓/✗) derived from RevokedCert table
    def revoked_local(self, obj):
        return RevokedCert.objects.filter(
            ca=obj.ca, serial_decimal=obj.serial_decimal
        ).exists()
    revoked_local.boolean = True
    revoked_local.short_description = "Revoked"

    def revoked_at_local(self, obj):
        rc = (
            RevokedCert.objects
            .filter(ca=obj.ca, serial_decimal=obj.serial_decimal)
            .order_by("-id")
            .first()
        )
        return rc.revoked_at if rc else None
    revoked_at_local.short_description = "Revoked at"

    # ----- save: parse CN/serial and auto-build p12 if cert+key provided -----
    def save_model(self, request, obj, form, change):
        # Parse CN/serial from uploaded cert (PEM/DER)
        raw = None
        uploaded_cert = form.cleaned_data.get("cert_pem")
        if uploaded_cert and hasattr(uploaded_cert, "read"):
            try:
                raw = uploaded_cert.read()
                uploaded_cert.seek(0)
            except Exception:
                raw = None
        if raw is None and obj.cert_pem:
            try:
                with obj.cert_pem.open("rb") as fh:
                    raw = fh.read()
            except Exception:
                raw = None
        if raw:
            try:
                cn, hx, dec = parse_cert_pem_to_parts(raw)
                if cn:
                    obj.subject_cn = cn
                obj.serial_hex = hx
                obj.serial_decimal = dec
            except Exception as e:
                messages.warning(request, f"Could not parse certificate: {e}")

        # Save so files are persisted
        super().save_model(request, obj, form, change)

        # Keep local RevokedCert table in sync with admin toggles
        if getattr(obj, "revoked", False):
            if not obj.revoked_at:
                obj.revoked_at = timezone.now()
                obj.save(update_fields=["revoked_at"])
            RevokedCert.objects.update_or_create(
                ca=obj.ca,
                serial_decimal=obj.serial_decimal,
                defaults={
                    "reason": getattr(obj, "revoke_reason", "") or "",
                    "revoked_at": obj.revoked_at,
                },
            )
        else:
            RevokedCert.objects.filter(
                ca=obj.ca, serial_decimal=obj.serial_decimal
            ).delete()

        # Auto-create PKCS#12 if cert+key exist (best-effort; unchanged from your file)
        cert_bytes = None
        key_bytes = None
        try:
            if obj.cert_pem:
                with obj.cert_pem.open("rb") as f:
                    cert_bytes = f.read()
        except Exception:
            pass
        try:
            if obj.key_pem:
                with obj.key_pem.open("rb") as f:
                    key_bytes = f.read()
        except Exception:
            pass

        if cert_bytes and key_bytes:
            try:
                from cryptography import x509
                from cryptography.hazmat.primitives import serialization
                from .utils import to_pkcs12_bytes  # already imported at top, but safe

                try:
                    leaf = x509.load_pem_x509_certificate(cert_bytes)
                except Exception:
                    leaf = x509.load_der_x509_certificate(cert_bytes)
                key = serialization.load_pem_private_key(key_bytes, password=None)

                chain = []
                try:
                    if getattr(obj.ca, "cert_pem", ""):
                        chain.append(x509.load_pem_x509_certificate(obj.ca.cert_pem.encode("utf-8")))
                    elif getattr(obj.ca, "issuer_cert_pem", None):
                        with obj.ca.issuer_cert_pem.open("rb") as f:
                            chain.append(x509.load_pem_x509_certificate(f.read()))
                except Exception:
                    pass

                p12_bytes = to_pkcs12_bytes(
                    friendly_name=(obj.subject_cn or "certificate"),
                    key=key,
                    cert=leaf,
                    cas=chain or None,
                )
                serial_label = (obj.serial_hex or obj.serial_decimal or "cert").lower()
                obj.p12_file.save(
                    f"{obj.ca.slug}-{serial_label}.p12",
                    ContentFile(p12_bytes),
                    save=True,
                )
            except Exception as e:
                messages.warning(request, f"Could not generate PKCS#12: {e}")
