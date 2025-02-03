from django.db import models
from employee.models import Employee
from category.models import Category
# Create your models here.

class JobListing(models.Model):
    # employer = models.ForeignKey(Employee, on_delete=models.CASCADE, related_name='job_listings')
    categories = models.ManyToManyField(Category)
    title = models.CharField(max_length=50)
    company_name = models.CharField(max_length=50)
    company_image = models.ImageField(upload_to='Job_Listings/images/')
    description = models.TextField()
    requirements = models.TextField()
    location = models.CharField(max_length=50)
    date_posted = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.title} at {self.company_name}"