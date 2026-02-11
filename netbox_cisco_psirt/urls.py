from django.urls import path
from netbox.views.generic import ObjectChangeLogView
from . import models, views

urlpatterns = [
    # Advisories
    path('advisories/', views.AdvisoryListView.as_view(), name='advisory_list'),
    path('advisories/<int:pk>/', views.AdvisoryView.as_view(), name='advisory'),
    path('advisories/<int:pk>/changelog/', ObjectChangeLogView.as_view(), name='advisory_changelog', kwargs={'model': models.Advisory}),

    # Vulnerabilities
    path('vulnerabilities/', views.VulnerabilityListView.as_view(), name='vulnerability_list'),
    path('vulnerabilities/<int:pk>/', views.VulnerabilityView.as_view(), name='vulnerability'),
    path('vulnerabilities/<int:pk>/changelog/', ObjectChangeLogView.as_view(), name='vulnerability_changelog', kwargs={'model': models.Vulnerability}),
]
