from netbox.plugins import PluginMenuItem

menu_items = (
    PluginMenuItem(
        link='plugins:netbox_cisco_psirt:advisory_list',
        link_text='Advisories',
    ),
    PluginMenuItem(
        link='plugins:netbox_cisco_psirt:vulnerability_list',
        link_text='Vulnerabilities',
    ),
)
