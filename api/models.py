from django.db import models
from django.contrib.auth.models import User

class Scan(models.Model):
    id = models.CharField(max_length=50, primary_key=True)
    url = models.URLField()
    timestamp = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=[('scanning', 'Scanning'), ('completed', 'Completed'), ('failed', 'Failed')])
    progress = models.IntegerField(default=0)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True)

class Vulnerability(models.Model):
    scan = models.ForeignKey(Scan, related_name='vulnerabilities', on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    description = models.TextField()
    level = models.CharField(max_length=10, choices=[('high', 'High'), ('medium', 'Medium'), ('low', 'Low'), ('none', 'None')])
    details = models.TextField()
    recommendation = models.TextField()
    category = models.CharField(max_length=20, choices=[('sqlInjection', 'SQL Injection'), ('xss', 'XSS'), ('openPorts', 'Open Ports'), ('other', 'Other')])