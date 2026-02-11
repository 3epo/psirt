from netbox.views import generic
from . import models, tables

class AdvisoryListView(generic.ObjectListView):
    queryset = models.Advisory.objects.all()
    table = tables.AdvisoryTable

class AdvisoryView(generic.ObjectView):
    queryset = models.Advisory.objects.all()

class AdvisoryEditView(generic.ObjectEditView):
    queryset = models.Advisory.objects.all()

class AdvisoryDeleteView(generic.ObjectDeleteView):
    queryset = models.Advisory.objects.all()

class VulnerabilityListView(generic.ObjectListView):
    queryset = models.Vulnerability.objects.all()
    table = tables.VulnerabilityTable

class VulnerabilityView(generic.ObjectView):
    queryset = models.Vulnerability.objects.all()

class VulnerabilityEditView(generic.ObjectEditView):
    queryset = models.Vulnerability.objects.all()

class VulnerabilityDeleteView(generic.ObjectDeleteView):
    queryset = models.Vulnerability.objects.all()
