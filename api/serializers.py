from rest_framework import serializers
from .models import Scan, Vulnerability

class VulnerabilitySerializer(serializers.ModelSerializer):
    class Meta:
        model = Vulnerability
        fields = ['id', 'name', 'description', 'level', 'details', 'recommendation', 'category']

class ScanSerializer(serializers.ModelSerializer):
    vulnerabilities = serializers.SerializerMethodField()
    summary = serializers.SerializerMethodField()

    class Meta:
        model = Scan
        fields = ['id', 'url', 'timestamp', 'status', 'progress', 'vulnerabilities', 'summary']

    def get_vulnerabilities(self, obj):
        """Group vulnerabilities by category to match frontend expectations"""
        all_vulns = obj.vulnerabilities.all()
        
        return {
            'sqlInjection': VulnerabilitySerializer(
                all_vulns.filter(category='sqlInjection'), many=True
            ).data,
            'xss': VulnerabilitySerializer(
                all_vulns.filter(category='xss'), many=True
            ).data,
            'openPorts': VulnerabilitySerializer(
                all_vulns.filter(category='openPorts'), many=True
            ).data,
            'other': VulnerabilitySerializer(
                all_vulns.filter(category='other'), many=True
            ).data,
        }

    def get_summary(self, obj):
        return {
            'high': obj.vulnerabilities.filter(level='high').count(),
            'medium': obj.vulnerabilities.filter(level='medium').count(),
            'low': obj.vulnerabilities.filter(level='low').count(),
            'total': obj.vulnerabilities.count()
        }