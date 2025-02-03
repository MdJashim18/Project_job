from django.urls import path,include
from rest_framework.routers import DefaultRouter
from .views import JobListingListCreateView,JobListingDetailView
from . import views

router = DefaultRouter() 

router.register('list', views.JobListingViewset)
urlpatterns = [
    path('', include(router.urls)),
    path('job_create/', JobListingListCreateView.as_view(), name='job_create'),
    path('job_detail/<int:pk>/', JobListingDetailView.as_view(), name='job_detail'),
]