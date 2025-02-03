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

class EmployeeViewset(viewsets.ModelViewSet):
    queryset = models.Employee.objects.all()
    serializer_class = serializers.EmployeeSerializer


class EmployeeRegistrationApiView(APIView):
    serializer_class = serializers.RegistrationSerializer
   
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            confirm_link = f"http://127.0.0.1:8000/employee/active/{uid}/{token}"
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
        return redirect('login')
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