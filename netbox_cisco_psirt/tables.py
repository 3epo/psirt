import django_tables2 as tables
from netbox.tables import NetBoxTable
from .models import Advisory, Vulnerability

class AdvisoryTable(NetBoxTable):
    advisory_id = tables.Column(linkify=True)
    first_fixed = tables.Column()

    class Meta(NetBoxTable.Meta):
        model = Advisory
        fields = ('pk', 'advisory_id', 'title', 'sir', 'cvss_base_score', 'first_published', 'last_updated', 'first_fixed')
        default_columns = ('advisory_id', 'title', 'sir', 'cvss_base_score', 'first_fixed')

class VulnerabilityTable(NetBoxTable):
    device = tables.Column(linkify=True)
    advisory = tables.Column(linkify=True)
    
    # Custom colored column for Advisory SIR
    advisory_sir = tables.TemplateColumn(
        template_code="""
        {% if record.advisory.sir == 'Critical' %}
            <span class="badge bg-danger text-white">{{ record.advisory.sir }}</span>
        {% elif record.advisory.sir == 'High' %}
            <span class="badge bg-orange text-white">{{ record.advisory.sir }}</span>
        {% elif record.advisory.sir == 'Medium' %}
            <span class="badge bg-warning text-white">{{ record.advisory.sir }}</span>
        {% else %}
            <span class="badge bg-secondary text-white">{{ record.advisory.sir }}</span>
        {% endif %}
        """,
        verbose_name='Severity',
        order_by='advisory__sir'
    )
    
    # Access first_fixed from Advisory
    advisory_first_fixed = tables.Column(
        accessor='advisory.first_fixed',
        verbose_name='Fixed Versions',
        orderable=False
    )
    
    class Meta(NetBoxTable.Meta):
        model = Vulnerability
        fields = ('pk', 'device', 'advisory', 'advisory_sir', 'advisory_first_fixed', 'status')
        default_columns = ('device', 'advisory', 'advisory_sir', 'advisory_first_fixed', 'status')
