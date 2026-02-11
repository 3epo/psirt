from netbox.api.routers import NetBoxRouter
from . import views

router = NetBoxRouter()
router.register('advisories', views.AdvisoryViewSet)
router.register('vulnerabilities', views.VulnerabilityViewSet)

urlpatterns = router.urls
