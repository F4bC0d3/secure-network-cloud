from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('nids_logs/', views.nids_logs, name='nids_logs'),
    path('cloud_logs/', views.cloud_logs, name='cloud_logs'),
    path('cloud_functionality/', views.cloud_functionality, name='cloud_functionality'),
    path('upload/', views.upload_file, name='upload_file'),
    path('download/<int:file_id>/', views.download_file, name='download_file'),
    path('delete/<int:file_id>/', views.delete_file, name='delete_file'),]
