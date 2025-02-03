from django.db import models
from django.contrib.auth.models import User
# Create your models here.


class Employee(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    image = models.ImageField(upload_to='employee/images/', default='employee/images/default_image.jpg')
    mobile_no = models.CharField(max_length=12, default='0000000000')
    status = models.CharField(max_length=50, choices=[('user', 'user'), ('employee', 'employee')], default='user')
    
    def __str__(self):
        return f"{self.user.first_name} {self.user.last_name}"


    