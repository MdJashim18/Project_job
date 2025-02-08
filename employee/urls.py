
from rest_framework.routers import DefaultRouter
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from . import views
router = DefaultRouter()

router.register('list', views.EmployeeViewset) 
urlpatterns = [
    path('', include(router.urls)),
    path('register/', views.EmployeeRegistrationApiView.as_view(), name='register'),
    path('active/<uid64>/<token>/', views.activate, name = 'activate'),
    path('login/', views.EmployeeLoginApiView.as_view(), name='login'),
    path('logout/', views.EmployeeLogoutView.as_view(), name='logout'),
    path('verify_token/', views.VerifyTokenAPIView.as_view(), name='verify_token'),
    path('password-reset/', views.PasswordResetRequestView.as_view(), name='password_reset'),
    path('password-reset-confirm/<uidb64>/<token>/', views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
]
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)