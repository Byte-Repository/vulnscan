"""vulnscan URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/

Examples:
Function views:
    1. Add an import: from my_app import views
    2. Add a URL to urlpatterns: path('', views.home, name='home')

Class-based views:
    1. Add an import: from other_app.views import Home
    2. Add a URL to urlpatterns: path('', Home.as_view(), name='home')

Including another URLconf:
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns: path('blog/', include('blog.urls'))
"""

from django.urls import path
from . import views

# Application namespace
app_name = 'vulnscan'

# URL Patterns for the app
urlpatterns = [
    # View for displaying the scanner form
    path('network-scanner/', views.ScannerView.as_view(), name='form_scanner_view'),
    
    # View for performing the scan (POST request)
    path('perform-scan/', views.ScannerView.as_view(), name='post_form_scanner'),
    
    # View for listing the scanner history by type
    path('scanner-history/<str:type>/', views.ScannerHistoryListView.as_view(), name='scanner_type'),
    
    # View for listing hosts under a specific scanner history
    path('scanner-history/<int:scanner_history_id>/host/', views.HostListView.as_view(), name='host_list'),
    
    # View for listing OS matches for a specific host within a scanner history
    path('scanner-history/<int:scanner_history_id>/host/<int:host_id>/os_match/', 
         views.OperativeSystemMatchListView.as_view(), name='os_matches_list'),
    
    # View for listing ports of a specific host within a scanner history
    path('scanner-history/<int:scanner_history_id>/host/<int:host_id>/ports/', 
         views.PortListView.as_view(), name='host_ports_list'),
]
