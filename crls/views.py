# crls/views.py
import hashlib
import logging
import os
import re
from datetime import datetime, timezone as py_tz

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.files.base import ContentFile
from django.db.models import Exists, OuterRef, Q   # <-- Q added
from django.http import (
    FileResponse,
    Http404,
    HttpResponse,
    HttpResponseNotAllowed,
)
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.text import slugify
from django.views.decorators.csrf import csrf_exempt

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption

from .forms import (
    UploadCRLForm,
    CAAdminForm,
    IssueCertForm,
    RevokeIssuedCertForm,
    P12DownloadForm,
)
from .models import CA, CRL, HttpSource, IssuedCert, OpnsenseSource, RevokedCert
from .utils import (
    _b64url_decode,
    build_ocsp_response_bytes,
    create_leaf_signed_by_ca,
    fetch_from_http,
    fetch_from_opnsense,
    generate_crl_from_local_revokes,
    generate_internal_ca_pem,
    parse_and_normalize_crl,
    parse_cert_pem_to_parts,
    to_pkcs12_bytes,
    build_subject2,
    OcspNoMatch,      # <-- import sentinel
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Dashboard / Settings
# ---------------------------------------------------------------------------

@login_required
def home(request):
    cas = CA.objects.all().order_by("name")
    return render(request, "crls/home.html", {"cas": cas})


@login_required
def upload_crl(request):
    if request.method == "POST":
        form = UploadCRLForm(request.POST, request.FILES)
        if form.is_valid():
            ca = form.cleaned_data["ca"]
            up = form.cleaned_data["file"]
            raw = up.read()

            crl = CRL(ca=ca, source="manual")
            try:
                parse_and_normalize_crl(crl, raw)
                ts = int(timezone.now().timestamp())
                crl.original_file.save(f"{ca.slug}-{ts}.bin", ContentFile(raw), save=False)
                crl.save()
                messages.success(request, f"CRL uploaded for {ca.name}. Revoked={crl.revoked_count}")
                return redirect("home")
            except Exception as e:
                messages.error(request, f"Upload failed: {e}")
                return redirect("upload_crl")
    else:
        form = UploadCRLForm()

    return render(request, "crls/upload.html", {"form": form})


# ---------------------------------------------------------------------------
# Sync / CRL generation
# ---------------------------------------------------------------------------

@login_required
def sync_now(request, slug):
    ca = get_object_or_404(CA, slug=slug)

    raw = None
    source_label = None
    try:
        if hasattr(ca, "opnsense_source") and ca.opnsense_source.enabled:
            raw = fetch_from_opnsense(ca.opnsense_source)
            source_label = "opnsense"
        elif hasattr(ca, "http_source") and ca.http_source.enabled:
            raw = fetch_from_http(ca.http_source)
            source_label = "http"
        else:
            messages.error(request, "No sync source enabled for this CA.")
            return redirect("home")
    except Exception as e:
        messages.error(request, f"Sync failed: {e}")
        return redirect("home")

    crl = CRL(ca=ca, source=source_label)
    try:
        ts = int(timezone.now().timestamp())
        crl.original_file.save(f"{ca.slug}-{ts}.bin", ContentFile(raw), save=False)

        parse_and_normalize_crl(crl, raw)
        crl.save()
        messages.success(request, "CRL synced and saved.")
    except Exception as e:
        messages.error(request, f"Parse/save failed: {e}")

    return redirect("home")


def _refresh_crl_for_ca(ca: CA) -> CRL:
    """Build and store a CRL for a CA based on local RevokedCerts."""
    der, pem, last_u, next_u, count = generate_crl_from_local_revokes(ca)
    crl = CRL(
        ca=ca,
        source="manual",
        last_update=last_u,
        next_update=next_u,
        revoked_count=count,
        sha256=hashlib.sha256(der).hexdigest(),
    )
    ts = int(timezone.now().timestamp())
    crl.der_file.save(f"{ca.slug}-{ts}.crl", ContentFile(der), save=False)
    crl.pem_file.save(f"{ca.slug}-{ts}.pem", ContentFile(pem), save=False)
    crl.original_file.save(f"{ca.slug}-{ts}-orig.crl", ContentFile(der), save=False)
    crl.save()
    return crl


@login_required
def generate_crl(request, slug: str):
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    ca = get_object_or_404(CA, slug=slug)
    try:
        _refresh_crl_for_ca(ca)
        messages.success(request, f"CRL generated for {ca.name}.")
    except Exception as e:
        messages.error(request, f"CRL generation failed: {e}")

    return redirect("cert_manager_list")


# ---------------------------------------------------------------------------
# Public endpoints (CDP + OCSP)
# ---------------------------------------------------------------------------

def serve_crl_der(request, slug):
    ca = get_object_or_404(CA, slug=slug)
    crl = ca.latest_crl()
    if not crl or not crl.der_file:
        raise Http404("No CRL for this CA")
    return FileResponse(
        crl.der_file.open("rb"),
        content_type="application/pkix-crl",
        as_attachment=False,
        filename=f"{slug}.crl",
    )


def serve_crl_pem(request, slug):
    ca = get_object_or_404(CA, slug=slug)
    crl = ca.latest_crl()
    if not crl or not crl.pem_file:
        raise Http404("No CRL for this CA")
    return FileResponse(
        crl.pem_file.open("rb"),
        content_type="application/x-pem-file",
        as_attachment=False,
        filename=f"{slug}.pem",
    )


def _select_ca_for_ocsp():
    """
    CAs eligible to answer OCSP:
    - active
    - ocsp_signer enabled
    - have at least one CA cert available (issuer_cert_pem OR cert_pem)
    """
    return (
        CA.objects.filter(active=True, ocsp_signer__enabled=True)
          .filter(Q(issuer_cert_pem__isnull=False) | Q(cert_pem__isnull=False))
          .filter(Q(issuer_cert_pem__gt="") | Q(cert_pem__gt=""))
          .select_related("ocsp_signer")
    )


@csrf_exempt
def ocsp_post(request):
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    from cryptography.x509 import ocsp as ocsp_mod
    from cryptography.hazmat.primitives.serialization import Encoding

    req_der = request.body or b""

    for ca in _select_ca_for_ocsp():
        signer = getattr(ca, "ocsp_signer", None)
        if not signer or not signer.enabled:
            continue
        try:
            resp_der = build_ocsp_response_bytes(ca, signer, req_der)
            return HttpResponse(resp_der, content_type="application/ocsp-response")
        except OcspNoMatch:
            # Not for this CA; try the next one
            continue
        except Exception:
            logger.exception("OCSP build failed for CA=%s", ca.name)
            continue

    resp = ocsp_mod.OCSPResponseBuilder().build_unsuccessful(ocsp_mod.OCSPResponseStatus.UNAUTHORIZED)
    return HttpResponse(resp.public_bytes(Encoding.DER), content_type="application/ocsp-response")


def ocsp_get(request, b64):
    from cryptography.x509 import ocsp as ocsp_mod
    from cryptography.hazmat.primitives.serialization import Encoding

    try:
        req_der = _b64url_decode(b64)
    except Exception:
        resp = ocsp_mod.OCSPResponseBuilder().build_unsuccessful(ocsp_mod.OCSPResponseStatus.MALFORMED_REQUEST)
        return HttpResponse(resp.public_bytes(Encoding.DER), content_type="application/ocsp-response")

    for ca in _select_ca_for_ocsp():
        signer = getattr(ca, "ocsp_signer", None)
        if not signer or not signer.enabled:
            continue
        try:
            resp_der = build_ocsp_response_bytes(ca, signer, req_der)
            return HttpResponse(resp_der, content_type="application/ocsp-response")
        except OcspNoMatch:
            continue
        except Exception:
            logger.exception("OCSP build failed (GET) for CA=%s", ca.name)
            continue

    resp = ocsp_mod.OCSPResponseBuilder().build_unsuccessful(ocsp_mod.OCSPResponseStatus.UNAUTHORIZED)
    return HttpResponse(resp.public_bytes(Encoding.DER), content_type="application/ocsp-response")


# ---------------------------------------------------------------------------
# Cert Manager (non-admin)
# ---------------------------------------------------------------------------

@login_required
def cert_manager_list(request):
    cas = CA.objects.all().order_by("name")
    return render(request, "cert_manager_list.html", {"cas": cas})


@login_required
def cert_manager_add(request):
    if request.method == "POST":
        form = CAAdminForm(request.POST, request.FILES)
        if form.is_valid():
            ca = form.save(commit=False)

            if form.cleaned_data.get("method") == CAAdminForm.METHOD_INTERNAL:
                parent = None
                if form.cleaned_data.get("issuer_mode") == "parent":
                    parent = form.cleaned_data.get("issuer_parent")

                cert_pem, key_pem = generate_internal_ca_pem(
                    common_name=form.cleaned_data.get("common_name") or ca.name,
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
                ca.cert_pem = cert_pem
                ca.key_pem = key_pem

            if not ca.slug:
                ca.slug = slugify(ca.name)

            ca.save()
            messages.success(request, "Certificate Authority created.")
            return redirect("cert_manager_list")
    else:
        form = CAAdminForm()

    return render(request, "cert_manager_form.html", {"form": form})


@login_required
def cm_download_cert(request, slug):
    ca = get_object_or_404(CA, slug=slug)
    if not getattr(ca, "cert_pem", ""):
        raise Http404("No stored CA certificate for this record.")
    data = ca.cert_pem.encode("utf-8")
    resp = HttpResponse(data, content_type="application/x-pem-file")
    resp["Content-Disposition"] = f'attachment; filename="{ca.slug}.pem"'
    return resp


@login_required
def cm_download_key(request, slug):
    ca = get_object_or_404(CA, slug=slug)
    if not getattr(ca, "key_pem", ""):
        raise Http404("No stored CA private key for this record.")
    data = ca.key_pem.encode("utf-8")
    resp = HttpResponse(data, content_type="application/x-pem-file")
    resp["Content-Disposition"] = f'attachment; filename="{ca.slug}-key.pem"'
    return resp


@login_required
def cm_download_p12(request, slug):
    """Build a PKCS#12 for a CA (no password)."""
    ca = get_object_or_404(CA, slug=slug)
    if not getattr(ca, "cert_pem", "") or not getattr(ca, "key_pem", ""):
        raise Http404("This CA does not have both cert and key stored.")

    cert = x509.load_pem_x509_certificate(ca.cert_pem.encode("utf-8"))
    key = serialization.load_pem_private_key(ca.key_pem.encode("utf-8"), password=None)
    pfx = to_pkcs12_bytes(ca.name, key, cert, cas=None)
    resp = HttpResponse(pfx, content_type="application/x-pkcs12")
    resp["Content-Disposition"] = f'attachment; filename="{ca.slug}.p12"'
    return resp


# Helpers for text extraction from uploads
def _get_uploaded_text(filefield):
    if not filefield:
        return ""
    data = filefield.read()
    try:
        return data.decode("utf-8", errors="ignore")
    except Exception:
        return data.decode("latin-1", errors="ignore")


@login_required
def cert_manager_issue(request):
    if request.method == "POST":
        form = IssueCertForm(request.POST, request.FILES)
        if form.is_valid():
            method = form.cleaned_data["method"]
            ca = form.cleaned_data["ca"]
            cert_type = form.cleaned_data["cert_type"]

            if method == "internal":
                subject = build_subject2(
                    common_name=form.cleaned_data.get("common_name") or "",
                    country_code=form.cleaned_data.get("country_code") or "",
                    state=form.cleaned_data.get("state") or "",
                    city=form.cleaned_data.get("city") or "",
                    organization=form.cleaned_data.get("organization") or "",
                    organizational_unit=form.cleaned_data.get("organizational_unit") or "",
                    email=form.cleaned_data.get("email") or "",
                )
                cert_pem, key_pem = create_leaf_signed_by_ca(
                    ca=ca,
                    cert_type=cert_type,
                    key_type=form.cleaned_data.get("key_type"),
                    digest_algo=form.cleaned_data.get("digest_algo"),
                    lifetime_days=form.cleaned_data.get("lifetime_days") or 397,
                    subject=subject,
                )

                ic = IssuedCert.objects.create(ca=ca)
                ts = int(timezone.now().timestamp())
                ic.cert_pem.save(f"{ca.slug}-{ts}.pem", ContentFile(cert_pem.encode("utf-8")), save=False)

                cn, sh, sd = parse_cert_pem_to_parts(cert_pem.encode("utf-8"))
                ic.subject_cn, ic.serial_hex, ic.serial_decimal = cn, sh, sd
                serial_label = (sh or sd or str(ts)).lower()

                ic.key_pem.save(
                    f"{ca.slug}-{serial_label}.key.pem",
                    ContentFile(key_pem.encode("utf-8")),
                    save=False,
                )

                # Try to build PKCS#12 bundle (no password)
                try:
                    leaf_cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
                    key_obj = serialization.load_pem_private_key(key_pem.encode("utf-8"), password=None)
                    chain = []
                    if getattr(ca, "cert_pem", ""):
                        chain.append(x509.load_pem_x509_certificate(ca.cert_pem.encode("utf-8")))
                    elif getattr(ca, "issuer_cert_pem", None):
                        with ca.issuer_cert_pem.open("rb") as f:
                            chain.append(x509.load_pem_x509_certificate(f.read()))
                    p12_bytes = to_pkcs12_bytes(
                        friendly_name=(cn or "certificate"),
                        key=key_obj,
                        cert=leaf_cert,
                        cas=chain or None,
                    )
                    ic.p12_file.save(f"{ca.slug}-{serial_label}.p12", ContentFile(p12_bytes), save=False)
                except Exception:
                    pass

                ic.save()
                messages.success(
                    request,
                    f"Certificate issued for CN={cn}. Permanent download links are available on the Issued Certificates page.",
                )
                return render(
                    request,
                    "cert_issue_done.html",
                    {"cert_pem": cert_pem, "key_pem": key_pem, "issued": ic, "issued_pk": ic.pk},
                )

            # Import existing cert
            else:
                cert_pem = form.cleaned_data.get("cert_pem") or _get_uploaded_text(request.FILES.get("cert_file"))

                ic = IssuedCert.objects.create(ca=ca)
                ts = int(timezone.now().timestamp())
                ic.cert_pem.save(f"{ca.slug}-{ts}.pem", ContentFile(cert_pem.encode("utf-8")), save=False)

                cn, sh, sd = parse_cert_pem_to_parts(cert_pem.encode("utf-8"))
                ic.subject_cn, ic.serial_hex, ic.serial_decimal = cn, sh, sd
                serial_label = (sh or sd or str(ts)).lower()

                key_text = ""
                if form.cleaned_data.get("import_key"):
                    key_text = form.cleaned_data.get("key_pem") or _get_uploaded_text(request.FILES.get("key_file"))

                if key_text:
                    ic.key_pem.save(
                        f"{ca.slug}-{serial_label}.key.pem",
                        ContentFile(key_text.encode("utf-8")),
                        save=False,
                    )

                    try:
                        leaf_cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
                        key_obj = serialization.load_pem_private_key(key_text.encode("utf-8"), password=None)
                        chain = []
                        if getattr(ca, "cert_pem", ""):
                            chain.append(x509.load_pem_x509_certificate(ca.cert_pem.encode("utf-8")))
                        elif getattr(ca, "issuer_cert_pem", None):
                            with ca.issuer_cert_pem.open("rb") as f:
                                chain.append(x509.load_pem_x509_certificate(f.read()))
                        p12_bytes = to_pkcs12_bytes(
                            friendly_name=(cn or "certificate"),
                            key=key_obj,
                            cert=leaf_cert,
                            cas=chain or None,
                        )
                        ic.p12_file.save(f"{ca.slug}-{serial_label}.p12", ContentFile(p12_bytes), save=False)
                    except Exception:
                        pass

                ic.save()
                messages.success(request, f"Certificate imported (CN={cn}).")
                return redirect("cert_manager_issued")
    else:
        form = IssueCertForm()

    return render(request, "cert_manager_issue.html", {"form": form})


@login_required
def cert_manager_issued(request):
    revoked_q = RevokedCert.objects.filter(
        ca=OuterRef("ca"),
        serial_decimal=OuterRef("serial_decimal"),
    )
    issued = (
        IssuedCert.objects.select_related("ca")
        .annotate(is_revoked=Exists(revoked_q))
        .order_by("-uploaded_at", "-id")
    )
    return render(request, "cert_manager_issued_list.html", {"issued": issued})


@login_required
def cert_manager_revoke(request, pk):
    cert = get_object_or_404(IssuedCert, pk=pk)

    if request.method == "POST":
        form = RevokeIssuedCertForm(request.POST)
        if form.is_valid():
            reason = form.cleaned_data.get("reason") or ""
            when = form.cleaned_data.get("revocation_date")

            rc, _ = RevokedCert.objects.update_or_create(
                ca=cert.ca,
                serial_decimal=cert.serial_decimal,
                defaults={"reason": reason},
            )
            if when:
                rc.revoked_at = when
                rc.save(update_fields=["revoked_at", "reason"])

            try:
                _refresh_crl_for_ca(cert.ca)
                messages.success(request, f"Serial {cert.serial_hex} revoked. CRL refreshed for {cert.ca.name}.")
            except Exception as e:
                messages.warning(request, f"Serial {cert.serial_hex} revoked, but CRL refresh failed: {e}")

            return redirect("cert_manager_issued")
    else:
        form = RevokeIssuedCertForm()

    return render(request, "cert_manager_revoke.html", {"form": form, "cert": cert})


# ---------------------------------------------------------------------------
# Issued cert downloads (cert/key/p12)
# ---------------------------------------------------------------------------

@login_required
def issued_download_cert(request, pk: int):
    ic = get_object_or_404(IssuedCert, pk=pk)
    data = ic.cert_pem.open("rb").read()
    name = (ic.subject_cn or ic.serial_hex or "certificate").replace("/", "_")
    resp = HttpResponse(data, content_type="application/x-pem-file")
    resp["Content-Disposition"] = f'attachment; filename="{name}.pem"'
    return resp


@login_required
def issued_download_key(request, pk: int):
    ic = get_object_or_404(IssuedCert, pk=pk)
    if not ic.key_pem:
        raise Http404("No private key stored for this certificate.")
    data = ic.key_pem.open("rb").read()
    name = (ic.subject_cn or ic.serial_hex or "key").replace("/", "_")
    resp = HttpResponse(data, content_type="application/x-pem-file")
    resp["Content-Disposition"] = f'attachment; filename="{name}-key.pem"'
    return resp


@login_required
def issued_download_p12(request, pk: int):
    ic = get_object_or_404(IssuedCert, pk=pk)
    display_name = (ic.subject_cn or ic.serial_hex or ic.serial_decimal or "certificate").replace("/", "_")

    if request.method == "POST":
        form = P12DownloadForm(request.POST)
        if form.is_valid():
            password = form.cleaned_data["password"]

            # Need both cert and key
            try:
                with ic.cert_pem.open("rb") as f:
                    cert_bytes = f.read()
                with ic.key_pem.open("rb") as f:
                    key_bytes = f.read()
            except Exception:
                messages.error(request, "Missing certificate or private key, cannot build PKCS#12.")
                return redirect("cert_manager_issued")

            try:
                try:
                    leaf = x509.load_pem_x509_certificate(cert_bytes)
                except Exception:
                    leaf = x509.load_der_x509_certificate(cert_bytes)

                key = serialization.load_pem_private_key(key_bytes, password=None)

                chain = []
                try:
                    if getattr(ic.ca, "cert_pem", ""):
                        chain.append(x509.load_pem_x509_certificate(ic.ca.cert_pem.encode("utf-8")))
                    elif getattr(ic.ca, "issuer_cert_pem", None):
                        with ic.ca.issuer_cert_pem.open("rb") as f:
                            chain.append(x509.load_pem_x509_certificate(f.read()))
                except Exception:
                    pass

                # Always encrypt with the provided password
                p12_bytes = serialize_key_and_certificates(
                    name=(ic.subject_cn or "certificate").encode("utf-8"),
                    key=key,
                    cert=leaf,
                    cas=chain or None,
                    encryption_algorithm=BestAvailableEncryption(password.encode("utf-8")),
                )

                resp = HttpResponse(p12_bytes, content_type="application/x-pkcs12")
                resp["Content-Disposition"] = f'attachment; filename="{display_name}.p12"'
                return resp

            except Exception as e:
                messages.error(request, f"Could not generate PKCS#12: {e}")
                return redirect("cert_manager_issued")
    else:
        form = P12DownloadForm()

    return render(request, "cert_manager_download_p12.html", {"cert": ic, "form": form})


# ---------------------------------------------------------------------------
# Logs (access, error, live)
# ---------------------------------------------------------------------------

# If your vhost uses different filenames, adjust these two:
ACCESS_LOG_PATH = "/var/log/apache2/crlserver_access.log"
ERROR_LOG_PATH  = "/var/log/apache2/crlserver_error.log"

# Live tail: ignore our own polling noise (and optionally the page hit)
LIVE_LOG_IGNORE_PATHS = [
    "/logs/access/live/poll",   # AJAX poll endpoint
    # "/logs/access/live/",     # uncomment to exclude the page GET itself
]

# Apache combined log timestamp like: [02/Oct/2025:11:30:12 +0300]
APACHE_DT_RE = re.compile(r"\[(?P<ts>\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+\-]\d{4})\]")

def _parse_apache_dt(s: str):
    try:
        return datetime.strptime(s, "%d/%b/%Y:%H:%M:%S %z")
    except Exception:
        return None

def _tail_lines(path: str, limit: int = 500):
    """Return last 'limit' lines of a file safely."""
    if not os.path.exists(path):
        return []
    limit = max(1, min(limit or 500, 5000))
    size = os.path.getsize(path)
    chunk = 8192
    with open(path, "rb") as f:
        seek = max(0, size - chunk)
        f.seek(seek)
        data = f.read()
        while data.count(b"\n") <= limit and seek > 0:
            seek = max(0, seek - chunk)
            f.seek(seek)
            data = f.read(size - seek)
    text = data.decode("utf-8", errors="replace")
    lines = text.splitlines()
    return lines[-limit:]

def _filter_by_params(lines, start_s: str|None, end_s: str|None, q: str|None):
    """Filter Apache log lines by timestamp range and substring match."""
    # parse query times (assume UTC from user input)
    def _parse_user_dt(val):
        if not val:
            return None
        for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(val, fmt)
                return dt.replace(tzinfo=py_tz.utc)
            except Exception:
                continue
        return None

    start_dt = _parse_user_dt(start_s)
    end_dt   = _parse_user_dt(end_s)

    out = []
    for ln in lines:
        if q and q.lower() not in ln.lower():
            continue
        if start_dt or end_dt:
            m = APACHE_DT_RE.search(ln)
            if not m:
                continue
            ap_dt = _parse_apache_dt(m.group("ts"))
            if not ap_dt:
                continue
            if start_dt and ap_dt < start_dt:
                continue
            if end_dt and ap_dt > end_dt:
                continue
        out.append(ln)
    return out

def _exclude_paths(lines, substrings):
    """Drop lines that contain any of the given substrings."""
    if not substrings:
        return lines
    out = []
    for ln in lines:
        if any(s in ln for s in substrings):
            continue
        out.append(ln)
    return out

@login_required
def logs_index(request):
    return render(request, "logs_index.html")

@login_required
def logs_access(request):
    limit = int(request.GET.get("limit") or 500)
    start = request.GET.get("start")
    end   = request.GET.get("end")
    q     = request.GET.get("q")

    lines = _tail_lines(ACCESS_LOG_PATH, limit=limit)
    lines = _filter_by_params(lines, start, end, q)
    text  = "\n".join(lines)

    ctx = {"title": "Access Logs",
           "path": ACCESS_LOG_PATH,
           "text": text,
           "limit": limit, "start": start or "", "end": end or "", "q": q or ""}
    return render(request, "logs_view.html", ctx)

@login_required
def logs_error(request):
    limit = int(request.GET.get("limit") or 500)
    start = request.GET.get("start")
    end   = request.GET.get("end")
    q     = request.GET.get("q")

    lines = _tail_lines(ERROR_LOG_PATH, limit=limit)
    lines = _filter_by_params(lines, start, end, q)
    text  = "\n".join(lines)

    ctx = {"title": "Error Logs",
           "path": ERROR_LOG_PATH,
           "text": text,
           "limit": limit, "start": start or "", "end": end or "", "q": q or ""}
    return render(request, "logs_view.html", ctx)

@login_required
def logs_access_live(request):
    """Simple live tail with polling (no SSE): page fetches /poll every 2s."""
    return render(request, "logs_live.html", {"path": ACCESS_LOG_PATH})

@login_required
def logs_access_live_poll(request):
    """Return last N lines for JS polling, excluding our own poll calls."""
    limit = int(request.GET.get("limit") or 200)
    limit = max(50, min(limit, 1000))

    # Oversample so that after filtering we still have ~limit lines
    raw = _tail_lines(ACCESS_LOG_PATH, limit=limit * 3)

    # Remove our own polling/page hits from the live view only
    filtered = _exclude_paths(raw, LIVE_LOG_IGNORE_PATHS)

    # Keep only the last 'limit' lines after filtering
    lines = filtered[-limit:]

    return HttpResponse("\n".join(lines), content_type="text/plain; charset=utf-8")
