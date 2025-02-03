from rest_framework import serializers
from .models import JobListing
from category.serializers import CategorySerializer
from category.models import Category


class JobListingSerializer(serializers.ModelSerializer):
    employer = serializers.StringRelatedField(read_only=True)
    categories = CategorySerializer(many=True,read_only=True)
    
    class Meta:
        model = JobListing
        fields = ['id', 'title', 'employer', 'description', 'requirements', 'location', 'date_posted' ,'company_image','categories']
        read_only_fields = ['date_posted', 'employer']
        
    