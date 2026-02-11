from django.core.management.base import BaseCommand
from dcim.models import Device
from netbox_cisco_psirt.models import Advisory, Vulnerability
from netbox_cisco_psirt.api import CiscoOpenVulnClient
from django.utils import timezone
import logging

class Command(BaseCommand):
    help = 'Fetches Cisco PSIRT advisories and updates device vulnerabilities.'

    def handle(self, *args, **kwargs):
        self.stdout.write("Starting Cisco PSIRT sync...")
        client = CiscoOpenVulnClient()

        # 1. Identify Cisco devices
        # This assumes manufacturer name contains 'Cisco'
        # Adjust filters based on your environment
        devices = Device.objects.filter(device_type__manufacturer__name__icontains='Cisco')
        
        # Group by OS version to reduce API calls
        # This assumes the platform name or a custom field holds the version
        # For simplicity, let's assume device.platform.name starts with 'Cisco IOS ' or similar
        # Or device.custom_fields['os_version']
        
        # We'll use a naive approach: Group devices by Platform Name
        version_map = {}
        for device in devices:
            if not device.platform:
                continue
            
            # Simple heuristic to extract version from platform name
            # e.g., "Cisco IOS 15.2(4)E" -> "15.2(4)E"
            # In a real scenario, this requires robust parsing logic
            version = device.platform.name.replace('Cisco IOS ', '').replace('Cisco IOS-XE ', '')
            
            if version:
                if version not in version_map:
                    version_map[version] = []
                version_map[version].append(device)

        for version, device_list in version_map.items():
            # Decide whether to call IOS or IOS-XE endpoint based on platform name of the first device
            # This is a heuristic; deeper logic might check Platform object fields
            platform_name = device_list[0].platform.name if device_list[0].platform else ""
            is_xe = (
                'IOS-XE' in platform_name 
                or 'ios-xe' in platform_name.lower()
                or version.startswith('16.')
                or version.startswith('17.')
            )
            
            self.stdout.write(f"Checking version: {version} (Type: {'IOS-XE' if is_xe else 'IOS'}) for {len(device_list)} devices...")

            advisories_data = []
            if is_xe:
                advisories_data = client.get_advisories_by_ios_xe(version)
            else:
                advisories_data = client.get_advisories_by_ios(version)
                
            if not advisories_data:
                self.stdout.write(f"No advisories found for {version}")
                continue
                
                # Parse firstFixed
                first_fixed = adv_data.get('firstFixed', [])
                
                # Create or update Advisory
                advisory, created = Advisory.objects.update_or_create(
                    advisory_id=adv_data.get('advisoryId'),
                    defaults={
                        'title': adv_data.get('advisoryTitle'),
                        'sir': adv_data.get('sir', 'Unknown'),
                        'cvss_base_score': float(adv_data.get('cvssBaseScore', 0.0)),
                        'publication_url': adv_data.get('publicationUrl'),
                        'first_fixed': first_fixed,
                        # 'first_published': ... parse date
                        # 'last_updated': ... parse date
                    }
                )
                
                # Link to devices
                for device in device_list:
                    Vulnerability.objects.get_or_create(
                        device=device,
                        advisory=advisory,
                        defaults={'status': Vulnerability.STATUS_ACTIVE}
                    )
                    
        self.stdout.write("Sync completed.")
