# crls/middleware.py
from urllib.parse import urlsplit

class AbsoluteFormURLMiddleware:
    """
    Normalize absolute-form request targets (e.g. 'POST http://host/ocsp')
    into origin-form (e.g. '/ocsp') so Django URL resolver matches.

    Handles odd dev-server variants like '/http:/host/ocsp' too.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        raw = request.path or ""
        # Fast check: do we see an absolute-ish form?
        if raw.startswith(("http://", "https://", "/http://", "/https://",
                           "http:/", "/http:/", "https:/", "/https:/")):
            s = raw.lstrip("/")  # strip leading slash if present

            # Fix single-slash forms from some clients/dev-server:
            # 'http:/host/...' -> 'http://host/...'
            if s.startswith("http:/") and not s.startswith("http://"):
                s = s.replace("http:/", "http://", 1)
            if s.startswith("https:/") and not s.startswith("https://"):
                s = s.replace("https:/", "https://", 1)

            try:
                parts = urlsplit(s)  # split absolute URL
                new_path = parts.path or "/"
                # Normalize both attributes used by Django
                request.path = new_path
                request.path_info = new_path
            except Exception:
                # If anything goes wrong, just fall through
                pass

        return self.get_response(request)
