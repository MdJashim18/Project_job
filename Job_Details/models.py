from django.db import models
from Job_Listings.models import JobListing
from employee.models import Employee

class Application(models.Model):
    job = models.ForeignKey(JobListing, related_name='applications', on_delete=models.CASCADE)
    employer = models.ForeignKey(Employee, on_delete=models.CASCADE, related_name='employer')
    applicant_name = models.CharField(max_length=50)
    email = models.EmailField()
    phone_number = models.CharField(max_length=12)
    resume = models.FileField(upload_to='Job_Details/resumes/')
    status = models.CharField(max_length=50, choices=[
        ('pending', 'Pending'),
        ('accepted', 'Accepted'),
        ('rejected', 'Rejected')
    ], default='pending')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Application for {self.job.title} by {self.applicant_name}"
