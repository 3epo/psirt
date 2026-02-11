from django.urls import path
from netbox.views.generic import ObjectChangeLogView
from . import models, views

urlpatterns = [
    # Advisories
    path('advisories/', views.AdvisoryListView.as_view(), name='advisory_list'),
    path('advisories/sync/', views.SyncCiscoPsirtView.as_view(), name='sync'),
    path('advisories/add/', views.AdvisoryEditView.as_view(), name='advisory_add'),
    path('advisories/<int:pk>/', views.AdvisoryView.as_view(), name='advisory'),
    path('advisories/<int:pk>/edit/', views.AdvisoryEditView.as_view(), name='advisory_edit'),
    path('advisories/<int:pk>/delete/', views.AdvisoryDeleteView.as_view(), name='advisory_delete'),
    path('advisories/<int:pk>/changelog/', ObjectChangeLogView.as_view(), name='advisory_changelog', kwargs={'model': models.Advisory}),

    # Vulnerabilities
    path('vulnerabilities/', views.VulnerabilityListView.as_view(), name='vulnerability_list'),
    path('vulnerabilities/add/', views.VulnerabilityEditView.as_view(), name='vulnerability_add'),
    path('vulnerabilities/<int:pk>/', views.VulnerabilityView.as_view(), name='vulnerability'),
    path('vulnerabilities/<int:pk>/edit/', views.VulnerabilityEditView.as_view(), name='vulnerability_edit'),
    path('vulnerabilities/<int:pk>/delete/', views.VulnerabilityDeleteView.as_view(), name='vulnerability_delete'),
    path('vulnerabilities/<int:pk>/changelog/', ObjectChangeLogView.as_view(), name='vulnerability_changelog', kwargs={'model': models.Vulnerability}),
]
