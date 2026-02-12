from netbox.api.viewsets import NetBoxModelViewSet
from .. import models
from .serializers import AdvisorySerializer, VulnerabilitySerializer

class AdvisoryViewSet(NetBoxModelViewSet):
    queryset = models.Advisory.objects.all()
    serializer_class = AdvisorySerializer

class VulnerabilityViewSet(NetBoxModelViewSet):
    queryset = models.Vulnerability.objects.all()
    serializer_class = VulnerabilitySerializer
    
