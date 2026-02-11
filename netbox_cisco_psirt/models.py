from django.db import models
from netbox.models import NetBoxModel

class Advisory(NetBoxModel):
    advisory_id = models.CharField(max_length=100, unique=True, help_text="Cisco Advisory ID")
    title = models.CharField(max_length=500)
    summary = models.TextField(blank=True)
    sir = models.CharField(max_length=20, help_text="Security Impact Rating (e.g., High, Medium, Critical)")
    cvss_base_score = models.FloatField(null=True, blank=True)
    publication_url = models.URLField(blank=True)
    first_published = models.DateTimeField(null=True, blank=True)
    last_updated = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ('-last_updated',)
        verbose_name_plural = 'Advisories'

    def __str__(self):
        return f"{self.advisory_id}: {self.title}"

class Vulnerability(NetBoxModel):
    device = models.ForeignKey(
        to='dcim.Device',
        on_delete=models.CASCADE,
        related_name='cisco_psirt_vulnerabilities',
        blank=True, null=True
    )
    # We might also want to support Module if needed, but starting with Device.
    
    advisory = models.ForeignKey(
        to=Advisory,
        on_delete=models.CASCADE,
        related_name='vulnerabilities'
    )
    
    STATUS_ACTIVE = 'active'
    STATUS_MITIGATED = 'mitigated'
    STATUS_IGNORED = 'ignored'
    
    STATUS_CHOICES = (
        (STATUS_ACTIVE, 'Active'),
        (STATUS_MITIGATED, 'Mitigated'),
        (STATUS_IGNORED, 'Ignored'),
    )
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_ACTIVE)

    class Meta:
        ordering = ('advisory__cvss_base_score',)
        verbose_name_plural = 'Vulnerabilities'
        unique_together = ('device', 'advisory')

    def __str__(self):
        return f"{self.device} - {self.advisory.advisory_id}"
