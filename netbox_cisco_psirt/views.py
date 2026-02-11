from netbox.views import generic
from django.shortcuts import redirect, render
from django.contrib import messages
from django.views.generic import View
from django.contrib.auth.mixins import PermissionRequiredMixin
from . import models, tables, forms
from .utilities import sync_cisco_psirt_data

class SyncCiscoPsirtView(PermissionRequiredMixin, View):
    permission_required = 'netbox_cisco_psirt.change_advisory'

    def post(self, request):
        try:
            sync_cisco_psirt_data()
            messages.success(request, "Cisco PSIRT sync completed successfully.")
        except Exception as e:
            messages.error(request, f"Sync failed: {e}")
        return redirect('plugins:netbox_cisco_psirt:advisory_list')

class AdvisoryListView(generic.ObjectListView):
    queryset = models.Advisory.objects.all()
    table = tables.AdvisoryTable
    template_name = 'netbox_cisco_psirt/advisory_list.html'

class AdvisoryView(generic.ObjectView):
    queryset = models.Advisory.objects.all()

class AdvisoryEditView(generic.ObjectEditView):
    queryset = models.Advisory.objects.all()
    form = forms.AdvisoryForm

class AdvisoryDeleteView(generic.ObjectDeleteView):
    queryset = models.Advisory.objects.all()

class VulnerabilityListView(generic.ObjectListView):
    queryset = models.Vulnerability.objects.all()
    table = tables.VulnerabilityTable

class VulnerabilityView(generic.ObjectView):
    queryset = models.Vulnerability.objects.all()

class VulnerabilityEditView(generic.ObjectEditView):
    queryset = models.Vulnerability.objects.all()
    form = forms.VulnerabilityForm

class VulnerabilityDeleteView(generic.ObjectDeleteView):
    queryset = models.Vulnerability.objects.all()
