from rest_framework import serializers
from .models import Application

class ApplicationSerializer(serializers.ModelSerializer):
    employer_name = serializers.CharField(source='employer.user.first_name', read_only=True)

    class Meta:
        model = Application
        fields = ['id', 'job', 'applicant_name', 'email', 'phone_number', 'resume', 'created_at', 'employer_name', 'status']
