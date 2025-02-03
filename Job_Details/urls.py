from django.urls import path, include
from rest_framework.routers import DefaultRouter
# from .views import JobViewSet, ApplicationViewSet
from .import views

router = DefaultRouter()

router.register('applications', views.ApplicationViewSet)

urlpatterns = [
    path('', include(router.urls)),
]

