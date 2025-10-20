# crls/management/commands/sync_crls.py
from django.core.management.base import BaseCommand
from django.utils import timezone
from crls.models import OpnsenseSource, CRL
from crls.utils import fetch_from_opnsense, parse_and_normalize_crl
from django.core.files.base import ContentFile

class Command(BaseCommand):
    help = "Sync CRLs from all enabled OPNsense sources"

    def handle(self, *args, **kwargs):
        count_ok = 0
        for src in OpnsenseSource.objects.filter(enabled=True):
            try:
                raw = fetch_from_opnsense(src)
                crl = CRL.objects.create(ca=src.ca, source='opnsense')
                crl.original_file.save(f"{src.ca.slug}-{int(timezone.now().timestamp())}.bin",
                                       ContentFile(raw), save=False)
                parse_and_normalize_crl(crl, raw)
                crl.save()
                src.last_sync = timezone.now()
                src.save(update_fields=['last_sync'])
                self.stdout.write(self.style.SUCCESS(f"Synced {src.ca.name}"))
                count_ok += 1
            except Exception as e:
                self.stderr.write(f"Failed {src.ca.name}: {e}")
        self.stdout.write(self.style.SUCCESS(f"Done. {count_ok} sources synced."))
