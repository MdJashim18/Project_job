from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import JobCategoryViewSet

router = DefaultRouter()
router.register('categories', JobCategoryViewSet)

urlpatterns = [
    path('', include(router.urls)),
]
