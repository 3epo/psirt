from dcim.models import Device
from netbox_cisco_psirt.models import Advisory, Vulnerability
from netbox_cisco_psirt.cisco_api import CiscoOpenVulnClient
import logging

logger = logging.getLogger(__name__)

def sync_cisco_psirt_data(stdout=None):
    """
    Synchronize Cisco PSIRT data.
    stdout: Optional output stream (e.g. for management command)
    """
    def log(msg):
        if stdout:
            stdout.write(msg)
        else:
            logger.info(msg)

    log("Starting Cisco PSIRT sync...")
    client = CiscoOpenVulnClient()

    # 1. Identify Cisco devices
    devices = Device.objects.filter(device_type__manufacturer__name__icontains='Cisco')
    
    version_map = {}
    for device in devices:
        if not device.platform:
            continue
        
        version = device.platform.name.replace('Cisco IOS ', '').replace('Cisco IOS-XE ', '')
        
        if version:
            if version not in version_map:
                version_map[version] = []
            version_map[version].append(device)

    for version, device_list in version_map.items():
        # Heuristic for IOS-XE
        platform_name = device_list[0].platform.name if device_list[0].platform else ""
        is_xe = (
            'IOS-XE' in platform_name 
            or 'ios-xe' in platform_name.lower()
            or version.startswith('16.')
            or version.startswith('17.')
        )
        
        log(f"Checking version: {version} (Type: {'IOS-XE' if is_xe else 'IOS'}) for {len(device_list)} devices...")

        advisories_data = []
        if is_xe:
            advisories_data = client.get_advisories_by_ios_xe(version)
        else:
            advisories_data = client.get_advisories_by_ios(version)
            
        if not advisories_data:
            log(f"No advisories found for {version}")
            continue
            
        # Collect all advisory IDs found for this version
        fetched_advisory_ids = []
        for adv_data in advisories_data:
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
                }
            )
            
            # Record the version that was checked and found to be affected
            current_versions = advisory.affected_versions or []
            if version not in current_versions:
                current_versions.append(version)
                advisory.affected_versions = current_versions
                advisory.save()
                
            fetched_advisory_ids.append(advisory.id)
            
            # Link to devices
            for device in device_list:
                Vulnerability.objects.get_or_create(
                    device=device,
                    advisory=advisory,
                    defaults={'status': Vulnerability.STATUS_ACTIVE}
                )
        
        # Cleanup: Remove vulnerabilities that are no longer applicable for these devices
        # (e.g. if device was upgraded and the old vuln is not in the new list)
        if fetched_advisory_ids:
            for device in device_list:
                deleted_count, _ = Vulnerability.objects.filter(device=device).exclude(advisory__id__in=fetched_advisory_ids).delete()
                if deleted_count > 0:
                    log(f"Device {device}: Deleted {deleted_count} obsolete vulnerabilities.")
    
    log("Sync completed.")
