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
    }

config = NetboxCiscoPsirtConfig
