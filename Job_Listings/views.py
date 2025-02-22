from rest_framework import generics, permissions, viewsets
from .import models
from .serializers import JobListingSerializer
from rest_framework.exceptions import PermissionDenied
from employee.models import Employee

# Corrected Viewset for JobListing
from rest_framework.permissions import AllowAny
from rest_framework.decorators import permission_classes
# from rest_framework import generics, permissions
# from rest_framework.exceptions import PermissionDenied

@permission_classes([AllowAny])
class JobListingViewset(viewsets.ModelViewSet):
    queryset = models.JobListing.objects.all()  # Should refer to JobListing model
    serializer_class = JobListingSerializer
    http_method_names = ['get', 'post', 'put', 'patch', 'delete']
    
    def update(self, request, *args, **kwargs):
        print("Received Data:", request.data)  # Debugging
        return super().update(request, *args, **kwargs)

class JobListingListCreateView(generics.ListCreateAPIView):
    queryset = models.JobListing.objects.all()
    serializer_class = JobListingSerializer
    # permission_classes = [permissions.IsAuthenticated]  # Uncomment if needed

    def perform_create(self, serializer):
        try:
            employer = self.request.user.employee
        except Employee.DoesNotExist:
            raise PermissionDenied("You must be an employer to create a job listing.")
        serializer.save(employer=employer)

    def get_queryset(self):
        if self.request.user.is_authenticated:
            return models.JobListing.objects.filter(employer=self.request.user.employee)
        return models.JobListing.objects.none()

class JobListingDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = models.JobListing.objects.all()
    serializer_class = JobListingSerializer
    
    

    def perform_update(self, serializer):
        job_listing = self.get_object()
        if job_listing.employer != self.request.user.employee:
            raise PermissionDenied("You are not allowed to update this job listing.")
        serializer.save()

    def perform_destroy(self, instance):
        if instance.employer != self.request.user.employee:
            raise PermissionDenied("You are not allowed to delete this job listing.")
        instance.delete()
