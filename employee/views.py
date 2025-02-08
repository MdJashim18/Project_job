from django.shortcuts import render
from rest_framework import viewsets
from . import models
from . import serializers
from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from rest_framework.authtoken.models import Token
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from rest_framework.permissions import AllowAny
from django.shortcuts import redirect
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import IsAuthenticated
from django.core.mail import send_mail
# from .serializers import PasswordResetSerializer, SetNewPasswordSerializer

class EmployeeViewset(viewsets.ModelViewSet):
    queryset = models.Employee.objects.all()
    serializer_class = serializers.EmployeeSerializer


class EmployeeRegistrationApiView(APIView):
    serializer_class = serializers.RegistrationSerializer
    permission_classes = [AllowAny]
   
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            confirm_link = f"https://project-job.onrender.com/employee/active/{uid}/{token}"
            email_subject = "Confirm Your Email"
            email_body = render_to_string('confirm_email.html', {'confirm_link': confirm_link})
            
            email = EmailMultiAlternatives(email_subject, '', to=[user.email])
            email.attach_alternative(email_body, "text/html")
            email.send()
            return Response({
                    'success': True,
                    'message': "Check your mail for confirmation"
                })
        return Response({
                'success': False,
                'error': serializer.errors
            })

def activate(request, uid64, token):
    try:
        uid = urlsafe_base64_decode(uid64).decode()
        user = User._default_manager.get(pk=uid)
    except(User.DoesNotExist):
        user = None 
    
    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        return redirect('http://127.0.0.1:63658/Login.html')
    else:
        return redirect('register')
    

class EmployeeLoginApiView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = serializers.EmployeeLoginSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']

            user = authenticate(username=username, password=password)
            
            if user:
                token, _ = Token.objects.get_or_create(user=user)
                
                try:
                    employee = models.Employee.objects.get(user=user)
                    if(employee):
                        status = 'employee'
                except models.Employee.DoesNotExist:
                    status = 'user'  
                
                login(request, user)
                return Response({
                    'token': token.key,
                    'user_id': user.id,
                    'role': status 
                })
            else:
                return Response({'error': "Invalid Credentials"}, status=400)
        return Response(serializer.errors, status=400)


class EmployeeLogoutView(APIView):
    def get(self, request):
        request.user.auth_token.delete()
        logout(request)
        return redirect('login')
    
class VerifyTokenAPIView(APIView):
    permission_classes = [IsAuthenticated]  

    def get(self, request):
        token = request.headers.get('Authorization')
        
        if not token:
            raise AuthenticationFailed('Token is missing')

        try:
          
            token = token.split(' ')[1]  
            user_token = Token.objects.get(key=token)
        except Token.DoesNotExist:
            raise AuthenticationFailed('Invalid token')

        user = user_token.user
        return Response({
            'success': True,
            'message': 'Token is valid',
            'user_id': user.id,
            'username': user.username
        }, status=200)




class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')

        if not User.objects.filter(email=email).exists():
            return Response({'error': "No user found with this email"}, status=400)

        user = User.objects.get(email=email)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        reset_link = f"https://yourfrontend.com/password-reset-confirm/{uid}/{token}/"

        send_mail(
            subject="Password Reset Request",
            message=f"Click the link below to reset your password:\n{reset_link}",
            from_email="your_email@example.com",
            recipient_list=[email],
            fail_silently=False,
        )

        return Response({'message': "Check your email for the reset link"}, status=200)


class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
        except (User.DoesNotExist, ValueError, TypeError):
            return Response({'error': "Invalid reset link"}, status=400)

        if not default_token_generator.check_token(user, token):
            return Response({'error': "Invalid or expired token"}, status=400)

        serializer = SetNewPasswordSerializer(data=request.data)
        if serializer.is_valid():
            user.set_password(serializer.validated_data['new_password'])
            user.save()
            return Response({'message': "Password reset successful"}, status=200)
        
        return Response(serializer.errors, status=400)