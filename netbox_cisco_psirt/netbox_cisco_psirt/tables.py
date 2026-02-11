import django_tables2 as tables
from netbox.tables import NetBoxTable
from .models import Advisory, Vulnerability

class AdvisoryTable(NetBoxTable):
    advisory_id = tables.Column(linkify=True)
    
    class Meta(NetBoxTable.Meta):
        model = Advisory
        fields = ('pk', 'advisory_id', 'title', 'sir', 'cvss_base_score', 'first_published', 'last_updated')
        default_columns = ('advisory_id', 'title', 'sir', 'cvss_base_score')

class VulnerabilityTable(NetBoxTable):
    device = tables.Column(linkify=True)
    advisory = tables.Column(linkify=True)
    
    class Meta(NetBoxTable.Meta):
        model = Vulnerability
        fields = ('pk', 'device', 'advisory', 'status')
        default_columns = ('device', 'advisory', 'status')
