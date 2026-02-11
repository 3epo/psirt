import django_tables2 as tables
from netbox.tables import NetBoxTable
from .models import Advisory, Vulnerability

class AdvisoryTable(NetBoxTable):
    advisory_id = tables.Column(linkify=True)
    
    class Meta(NetBoxTable.Meta):
        model = Advisory
    sir = tables.TemplateColumn(
        template_code="""
        {% if record.sir == 'Critical' %}
            <span class="badge bg-danger">{{ record.sir }}</span>
        {% elif record.sir == 'High' %}
            <span class="badge bg-orange">{{ record.sir }}</span>
        {% elif record.sir == 'Medium' %}
            <span class="badge bg-warning">{{ record.sir }}</span>
        {% else %}
            <span class="badge bg-secondary">{{ record.sir }}</span>
        {% endif %}
        """
    )
    first_fixed = tables.Column()

    class Meta(NetBoxTable.Meta):
        model = Advisory
        fields = ('pk', 'advisory_id', 'title', 'sir', 'cvss_base_score', 'first_published', 'last_updated', 'first_fixed')
        default_columns = ('advisory_id', 'title', 'sir', 'cvss_base_score', 'first_fixed')

class VulnerabilityTable(NetBoxTable):
    device = tables.Column(linkify=True)
    advisory = tables.Column(linkify=True)
    
    class Meta(NetBoxTable.Meta):
        model = Vulnerability
        fields = ('pk', 'device', 'advisory', 'status')
        default_columns = ('device', 'advisory', 'status')
