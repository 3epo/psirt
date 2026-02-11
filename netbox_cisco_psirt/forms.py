from netbox.forms import NetBoxModelForm
from .models import Advisory, Vulnerability

class AdvisoryForm(NetBoxModelForm):
    class Meta:
        model = Advisory
        fields = ('advisory_id', 'title', 'summary', 'sir', 'cvss_base_score', 'publication_url', 'first_published', 'last_updated', 'first_fixed')

class VulnerabilityForm(NetBoxModelForm):
    class Meta:
        model = Vulnerability
        fields = ('device', 'advisory', 'status')
