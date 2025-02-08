from rest_framework import serializers
from .models import JobListing
from category.serializers import CategorySerializer
from category.models import Category


class JobListingSerializer(serializers.ModelSerializer):
    employer = serializers.StringRelatedField(read_only=True)
    categories = CategorySerializer(many=True,read_only=True)
    
    class Meta:
        model = JobListing
        fields = '__all__'
        read_only_fields = ['date_posted', 'employer']
        
    def validate(self, data):
        if "title" not in data or "description" not in data:
            raise serializers.ValidationError("Title and description are required fields.")
        return data
        
    