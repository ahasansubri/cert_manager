# crls/urls.py
from django.urls import path
from . import views

urlpatterns = [
    # existing pages
    path("", views.home, name="home"),
    path("upload/", views.upload_crl, name="upload_crl"),
    path("sync/<slug:slug>/", views.sync_now, name="sync_now"),
    path("crl/generate/<slug:slug>/", views.generate_crl, name="generate_crl"),

    # public endpoints
    path("pki/<slug:slug>.crl", views.serve_crl_der, name="serve_crl_der"),
    path("pki/<slug:slug>.pem", views.serve_crl_pem, name="serve_crl_pem"),
    path("ocsp/<str:b64>", views.ocsp_get, name="ocsp_get"),
    path("ocsp/", views.ocsp_post, name="ocsp_post"),
    path("ocsp",  views.ocsp_post, name="ocsp_post_noslash"),

    # Cert Manager
    path("cert-manager/", views.cert_manager_list, name="cert_manager_list"),
    path("cert-manager/add/", views.cert_manager_add, name="cert_manager_add"),
    path("cert-manager/<slug:slug>/download/cert/", views.cm_download_cert, name="cm_download_cert"),
    path("cert-manager/<slug:slug>/download/key/", views.cm_download_key, name="cm_download_key"),
    path("cert-manager/<slug:slug>/download/p12/", views.cm_download_p12, name="cm_download_p12"),

    # Issue / Issued certs
    path("cert-manager/issue/", views.cert_manager_issue, name="cert_manager_issue"),
    path("cert-manager/issued/", views.cert_manager_issued, name="cert_manager_issued"),
    path("cert-manager/issued/<int:pk>/revoke/", views.cert_manager_revoke, name="cert_manager_revoke"),

    # Permanent downloads for issued certs
    path("issued/<int:pk>/cert.pem",  views.issued_download_cert, name="issued_download_cert"),
    path("issued/<int:pk>/key.pem",   views.issued_download_key,  name="issued_download_key"),
    path("issued/<int:pk>/bundle.p12", views.issued_download_p12, name="issued_download_p12"),

    # -------- Logs --------
    path("logs/", views.logs_index, name="logs_index"),
    path("logs/access/", views.logs_access, name="logs_access"),
    path("logs/error/",  views.logs_error,  name="logs_error"),
    path("logs/access/live/", views.logs_access_live, name="logs_access_live"),
    path("logs/access/live/poll/", views.logs_access_live_poll, name="logs_access_live_poll"),
]
