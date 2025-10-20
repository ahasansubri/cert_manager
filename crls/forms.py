from django import forms
from django.utils.translation import gettext_lazy as _
from .models import CA, IssuedCert

# --- Admin: simple pass-through form for CA (fixes ImportError) ---

def _read_utf8(uploaded_file):
    if not uploaded_file:
        return ""
    data = uploaded_file.read()
    try:
        return data.decode("utf-8")
    except Exception:
        return data.decode("latin-1", errors="ignore")

class CAAdminForm(forms.ModelForm):
    """
    Admin 'Add CA' / 'Change CA' form that supports:
      - Import existing CA (paste PEM, optional file uploads)
      - Create internal CA (self-signed or signed by an existing CA)
    The generated material for the internal method is produced in admin.save_model().
    """

    # --- Mode selector
    METHOD_IMPORT = "import"
    METHOD_INTERNAL = "internal"
    method = forms.ChoiceField(
        label=_("Method"),
        choices=(
            (METHOD_IMPORT, _("Import existing CA")),
            (METHOD_INTERNAL, _("Create internal CA")),
        ),
        initial=METHOD_IMPORT,
        help_text=_("Choose how you want to populate this CA."),
        required=True,
    )

    # --- Internal CA options (not persisted on the model)
    issuer_mode = forms.ChoiceField(
        label=_("Issuer"),
        choices=(("self", _("Self-signed")), ("parent", _("Signed by existing CA"))),
        required=False,
        initial="self",
    )
    issuer_parent = forms.ModelChoiceField(
        label=_("Parent CA"),
        queryset=CA.objects.all(),
        required=False,
        help_text=_("Used when Issuer = 'Signed by existing CA'."),
    )

    key_type = forms.ChoiceField(
        label=_("Key type"),
        choices=(
            ("rsa2048", "RSA 2048"),
            ("rsa4096", "RSA 4096"),
            ("ec-p256", "EC P-256"),
            ("ec-p384", "EC P-384"),
        ),
        initial="rsa2048",
        required=False,
    )
    digest_algo = forms.ChoiceField(
        label=_("Digest algo"),
        choices=(("sha256", "SHA256"), ("sha384", "SHA384"), ("sha512", "SHA512")),
        initial="sha256",
        required=False,
    )
    lifetime_days = forms.IntegerField(
        label=_("Lifetime (days)"),
        initial=825,
        min_value=1,
        required=False,
    )

    # Subject (internal CA only; not stored on the CA model)
    common_name = forms.CharField(label=_("Common Name"), required=False)
    country_code = forms.CharField(label=_("Country Code"), required=False, max_length=2)
    state = forms.CharField(label=_("State or Province"), required=False)
    city = forms.CharField(label=_("City"), required=False)
    organization = forms.CharField(label=_("Organization"), required=False)
    organizational_unit = forms.CharField(label=_("Organizational Unit"), required=False)
    email = forms.EmailField(label=_("Email"), required=False)
    ocsp_uri = forms.CharField(label=_("OCSP URI"), required=False)

    # --- Import helpers (files). These do NOT replace your existing textareas;
    #     we merge file -> text so the model fields keep the PEMs.
    cert_file = forms.FileField(label=_("Or Certificate file (PEM)"), required=False)
    key_file = forms.FileField(label=_("Or Private key file (PEM)"), required=False)

    class Meta:
        model = CA
        fields = [
            # identity
            "name", "slug", "active",
            # issuer file on the model (used by both methods if you want to keep chain)
            "issuer_cert_pem",
            # stored PEM text fields on the model (used for Import; filled for Internal in admin.save_model)
            "cert_pem", "key_pem",
            # issuance control
            "next_serial",
        ]
        help_texts = {
            "issuer_cert_pem": _("Your issuer/public certificate (PEM)."),
            "cert_pem": _("Optional: paste CA certificate PEM here (Import method)."),
            "key_pem": _("Optional: paste CA private key PEM here (Import method)."),
        }
        widgets = {
            "cert_pem": forms.Textarea(attrs={"rows": 12}),
            "key_pem": forms.Textarea(attrs={"rows": 12}),
        }
        label = {
            "cert_pem": _("Certificate Data (PEM)")
        }

    # --- Validation
    def clean(self):
        cleaned = super().clean()
        method = cleaned.get("method")

        if method == self.METHOD_IMPORT:
            # Need a certificate either pasted or uploaded
            txt = cleaned.get("cert_pem") or ""
            if not txt and self.files.get("cert_file"):
                txt = _read_utf8(self.files["cert_file"])
                cleaned["cert_pem"] = txt
            if not txt:
                raise forms.ValidationError(_("Please provide a certificate (paste or upload)."))

            # Optional key
            key_txt = cleaned.get("key_pem") or ""
            if not key_txt and self.files.get("key_file"):
                key_txt = _read_utf8(self.files["key_file"])
                cleaned["key_pem"] = key_txt

        else:  # internal
            # Require CN; if parent selected, require issuer_parent
            cn = cleaned.get("common_name") or ""
            if not cn:
                raise forms.ValidationError(_("Common Name is required for an internal CA."))
            if cleaned.get("issuer_mode") == "parent" and not cleaned.get("issuer_parent"):
                raise forms.ValidationError(_("Please select a parent CA (or choose Self-signed)."))

            # For internal creation we ignore any pasted/imported cert/key
            cleaned["cert_pem"] = cleaned.get("cert_pem") or ""
            cleaned["key_pem"] = cleaned.get("key_pem") or ""

        return cleaned

    def save(self, commit=True):
        """
        For 'import': copy uploaded files into cert_pem/key_pem text fields.
        For 'internal': leave generation to CAAdmin.save_model().
        """
        obj = super().save(commit=False)
        if self.cleaned_data.get("method") == self.METHOD_IMPORT:
            # Files already merged into cleaned_data in clean()
            obj.cert_pem = self.cleaned_data.get("cert_pem") or ""
            obj.key_pem = self.cleaned_data.get("key_pem") or ""
        if commit:
            obj.save()
            self.save_m2m()
        return obj

    class Media:
        # Adds a tiny JS to toggle the admin form sections
        js = ("crls/ca_admin.js",)


# --- Existing: Upload CRL (unchanged behavior) ---
class UploadCRLForm(forms.Form):
    ca = forms.ModelChoiceField(
        queryset=CA.objects.all().order_by("name"),
        label="CA",
    )
    file = forms.FileField(
        label="CRL File",
        help_text="PEM or DER",
    )


# --- New: Issuance form (internal / sign CSR / import) for Cert Manager ---
class IssueCertForm(forms.Form):
    METHOD_CHOICES = (
        ("internal", "Create internal certificate"),
        ("import", "Import existing certificate"),
    )
    CERT_TYPE_CHOICES = (
        ("client", "Client Certificate"),
        ("server", "Server Certificate"),
    )
    KEY_TYPE_CHOICES = (
        ("RSA-2048", "RSA-2048"),
        ("RSA-4096", "RSA-4096"),
        ("EC-P256", "EC-P256"),
        ("EC-P384", "EC-P384"),
    )
    DIGEST_CHOICES = (("SHA256", "SHA256"), ("SHA384", "SHA384"), ("SHA512", "SHA512"))

    # --- common ---
    method = forms.ChoiceField(choices=METHOD_CHOICES, initial="internal", label="Method")
    ca = forms.ModelChoiceField(queryset=CA.objects.filter(active=True), label="Issuer (CA)")
    cert_type = forms.ChoiceField(choices=CERT_TYPE_CHOICES, initial="client", label="Type")

    # --- internal only ---
    key_type = forms.ChoiceField(choices=KEY_TYPE_CHOICES, initial="RSA-2048", label="Key type", required=False)
    digest_algo = forms.ChoiceField(choices=DIGEST_CHOICES, initial="SHA256", label="Digest algo", required=False)
    lifetime_days = forms.IntegerField(initial=397, min_value=1, max_value=825, required=False, label="Lifetime (days)")

    # subject (internal only)
    common_name = forms.CharField(max_length=255, required=False)
    country_code = forms.CharField(max_length=2, required=False, label="Country Code")
    state = forms.CharField(max_length=128, required=False, label="State or Province")
    city = forms.CharField(max_length=128, required=False)
    organization = forms.CharField(max_length=255, required=False)
    organizational_unit = forms.CharField(max_length=255, required=False)
    email = forms.EmailField(required=False)

    # --- import only ---
    cert_pem = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={"rows": 10}),
        label="Certificate (PEM)",
        help_text="Paste certificate in PEM format or upload a file below.",
    )
    cert_file = forms.FileField(required=False, label="Or upload certificate file (PEM)")

    import_key = forms.BooleanField(required=False, initial=False, label="Import private key too")
    key_pem = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={"rows": 8}),
        label="Private key (PEM)",
        help_text="Paste key in PEM format or upload a file below.",
    )
    key_file = forms.FileField(required=False, label="Or upload key file (PEM)")

    def clean(self):
        cleaned = super().clean()
        method = cleaned.get("method")

        if method == "internal":
            # Require CN for internal issuance
            if not cleaned.get("common_name"):
                self.add_error("common_name", "Common Name is required for internal issuance.")
        else:
            # import mode: require cert (either textarea or file)
            if not cleaned.get("cert_pem") and not cleaned.get("cert_file"):
                self.add_error("cert_pem", "Provide a certificate (paste or file upload).")

            # If user wants to import the key, require it (textarea or file)
            if cleaned.get("import_key"):
                if not cleaned.get("key_pem") and not cleaned.get("key_file"):
                    self.add_error("key_pem", "Provide a private key (paste or file upload).")

        return cleaned

# --- New: Revocation form (used by cert_manager_revoke) ---
class RevokeIssuedCertForm(forms.Form):
    REASON_CHOICES = (
        ("unspecified", "Unspecified"),
        ("key_compromise", "Key compromise"),
        ("ca_compromise", "CA compromise"),
        ("affiliation_changed", "Affiliation changed"),
        ("superseded", "Superseded"),
        ("cessation_of_operation", "Cessation of operation"),
        ("certificate_hold", "Certificate hold"),
        ("remove_from_crl", "Remove from CRL"),
        ("privilege_withdrawn", "Privilege withdrawn"),
        ("aa_compromise", "AA compromise"),
    )
    reason = forms.ChoiceField(choices=REASON_CHOICES, initial="unspecified")
    revocation_date = forms.DateTimeField(
        required=False,
        help_text="If empty, current time will be used.",
    )

# --- NEW: Optional password prompt for PKCS#12 download (Issued certs) ---
class P12DownloadForm(forms.Form):
    password = forms.CharField(
        max_length=128,
        required=True,
        widget=forms.PasswordInput(render_value=True, attrs={"class": "form-control"}),
        help_text="Enter a password to protect the PKCS#12 bundle.",
        label="Password"
    )
