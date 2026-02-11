import requests
import logging
from django.conf import settings
from datetime import datetime

logger = logging.getLogger(__name__)

class CiscoOpenVulnClient:
    TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token"
    API_BASE = "https://api.cisco.com/security/advisories/v2"

    def __init__(self):
        plugin_config = settings.PLUGINS_CONFIG.get('netbox_cisco_psirt', {})
        self.client_id = plugin_config.get('cisco_client_id')
        self.client_secret = plugin_config.get('cisco_client_secret')
        self.token = None

    def _authenticate(self):
        if not self.client_id or not self.client_secret:
            logger.error("Cisco API credentials not configured.")
            return

        response = requests.post(
            self.TOKEN_URL,
            data={'grant_type': 'client_credentials'},
            auth=(self.client_id, self.client_secret),
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )
        
        if response.status_code == 200:
            self.token = response.json().get('access_token')
        else:
            logger.error(f"Failed to authenticate with Cisco API: {response.text}")
            raise Exception("Authentication failed")

    def get_headers(self):
        if not self.token:
            self._authenticate()
        return {
            'Authorization': f"Bearer {self.token}",
            'Accept': 'application/json'
        }

    def get_advisories_by_ios(self, version):
        """
        Fetch advisories for a specific IOS version.
        Note: The API endpoint might vary based on checks.
        Using the 'ios' endpoint as an example.
        """
        url = f"{self.API_BASE}/ios?version={version}"
        try:
            response = requests.get(url, headers=self.get_headers())
            response.raise_for_status()
            return response.json().get('advisories', [])
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching advisories for version {version}: {e}")
            return []

    def get_advisories_by_ios_xe(self, version):
        """
        Fetch advisories for a specific IOS-XE version.
        """
        url = f"{self.API_BASE}/iosxe?version={version}"
        try:
            response = requests.get(url, headers=self.get_headers())
            response.raise_for_status()
            return response.json().get('advisories', [])
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching advisories for version {version}: {e}")
            return []

    # Add more methods as needed (e.g., all advisories, or by CVD)
