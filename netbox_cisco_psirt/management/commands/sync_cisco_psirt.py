from django.core.management.base import BaseCommand
from netbox_cisco_psirt.utilities import sync_cisco_psirt_data

class Command(BaseCommand):
    help = 'Fetches Cisco PSIRT advisories and updates device vulnerabilities.'

    def handle(self, *args, **kwargs):
        self.stdout.write("Starting Cisco PSIRT sync...")
        try:
            sync_cisco_psirt_data(self.stdout)
            self.stdout.write(self.style.SUCCESS("Sync completed successfully."))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Sync failed: {e}"))
