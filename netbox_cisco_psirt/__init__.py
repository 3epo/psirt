from netbox.plugins import PluginConfig

class NetboxCiscoPsirtConfig(PluginConfig):
    name = 'netbox_cisco_psirt'
    verbose_name = 'Cisco PSIRT'
    description = 'Track Cisco PSIRT advisories for your devices'
    version = '0.1.0'
    base_url = 'cisco-psirt'
    author = 'Andrey Orlov'
    author_email = 'andreyorlov@example.com'
    required_settings = []
    default_settings = {
        'cisco_client_id': '',
        'cisco_client_secret': '',
        # SMTP Notifications
        'smtp_enabled': False,
        'smtp_host': '',
        'smtp_port': 587,
        'smtp_use_tls': True,
        'smtp_use_ssl': False,
        'smtp_username': '',
        'smtp_password': '',
        'smtp_from': '',
        'smtp_to': '',          # comma-separated list of recipients
    }

config = NetboxCiscoPsirtConfig
