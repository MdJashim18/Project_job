from rest_framework import viewsets, status
from django.shortcuts import get_object_or_404
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from rest_framework.response import Response
from employee.models import Employee
from .models import Application
from .serializers import ApplicationSerializer


class ApplicationViewSet(viewsets.ModelViewSet):
    queryset = Application.objects.all()
    serializer_class = ApplicationSerializer
  
    def perform_create(self, serializer):
        if not self.request.user or self.request.user.is_anonymous:
            return Response({"error": "Authentication required"}, status=status.HTTP_401_UNAUTHORIZED)

        employer = Employee.objects.filter(user=self.request.user).first()
        if not employer:
            return Response({"error": "Employer not found"}, status=status.HTTP_400_BAD_REQUEST)
 
        application = serializer.save(employer=employer)

        if not application.email:
            return Response({"error": "Applicant email is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            applicant_subject = "Application Received"
            applicant_message = render_to_string('application_received.html', {'application': application})
            applicant_plain_message = strip_tags(applicant_message)

            send_mail(
                subject=applicant_subject,
                message=applicant_plain_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[application.email],
                html_message=applicant_message,
            )
        except Exception as e:
            print(f"Error sending email: {e}") 
