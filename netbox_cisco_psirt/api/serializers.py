from netbox.api.serializers import NetBoxModelSerializer
from .models import Advisory, Vulnerability

class AdvisorySerializer(NetBoxModelSerializer):
    class Meta:
        model = Advisory
        fields = (
            'id', 'advisory_id', 'title', 'summary', 'sir', 'cvss_base_score', 
            'publication_url', 'first_published', 'last_updated', 'first_fixed',
            'created', 'last_updated',
        )

class VulnerabilitySerializer(NetBoxModelSerializer):
    class Meta:
        model = Vulnerability
        fields = (
            'id', 'device', 'advisory', 'status',
            'created', 'last_updated',
        )
