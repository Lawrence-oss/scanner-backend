import logging
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Scan, Vulnerability
from .serializers import ScanSerializer
import nmap
from bs4 import BeautifulSoup
import requests
from django.utils import timezone
import threading
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class ScanView(APIView):
    def post(self, request):
        """Start a new security scan"""
        logger.info("Received POST request to /api/scan/")
        url = request.data.get('url')
        logger.info(f"URL: {url}")
        
        if not url:
            logger.error("URL is required")
            return Response({'error': 'URL is required'}, status=status.HTTP_400_BAD_REQUEST)

        # Validate URL format
        try:
            parsed_url = urlparse(url)
            if not parsed_url.scheme:
                url = f"https://{url}"  # Add https if no scheme
                parsed_url = urlparse(url)
            
            if not parsed_url.netloc:
                return Response({'error': 'Invalid URL format'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': f'Invalid URL: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)

        # Create scan record
        scan_id = str(int(timezone.now().timestamp() * 1000))  # Use milliseconds for uniqueness
        scan = Scan.objects.create(
            id=scan_id, 
            url=url, 
            status='scanning', 
            progress=0,
            user=request.user if request.user.is_authenticated else None
        )
        logger.info(f"Created scan with ID: {scan_id}")

        # Start scan in background thread
        thread = threading.Thread(target=self._perform_scan, args=(scan,))
        thread.daemon = True
        thread.start()

        # Return scan info immediately
        serializer = ScanSerializer(scan)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def get(self, request, scan_id=None):
        """Get scan results by ID"""
        logger.info(f"Received GET request for scan ID: {scan_id}")
        
        if not scan_id:
            return Response({'error': 'Scan ID is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            scan = Scan.objects.get(id=scan_id)
            serializer = ScanSerializer(scan)
            logger.info(f"Found scan {scan_id}, status: {scan.status}, progress: {scan.progress}")
            return Response(serializer.data)
        except Scan.DoesNotExist:
            logger.error(f"Scan not found: {scan_id}")
            return Response({'error': 'Scan not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Error retrieving scan {scan_id}: {str(e)}")
            return Response({'error': 'Internal server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def _perform_scan(self, scan):
        """Perform the actual security scan in background"""
        try:
            logger.info(f"Starting background scan for {scan.url}")
            
            # Step 1: Update progress
            scan.progress = 20
            scan.save()
            
            # Step 2: Port scanning with nmap
            self._scan_ports(scan)
            scan.progress = 60
            scan.save()
            
            # Step 3: Web scraping and analysis
            self._analyze_website(scan)
            scan.progress = 80
            scan.save()
            
            # Step 4: Additional security checks could go here
            scan.progress = 90
            scan.save()
            
            # Step 5: Complete
            scan.status = 'completed'
            scan.progress = 100
            scan.save()
            logger.info(f"Scan {scan.id} completed successfully")
            
        except Exception as e:
            logger.error(f"Scan {scan.id} failed: {str(e)}", exc_info=True)
            scan.status = 'failed'
            scan.progress = 0
            scan.save()
            
            # Create error vulnerability
            Vulnerability.objects.create(
                scan=scan,
                name="Scan Error",
                description="An error occurred during scanning",
                level='none',
                details=str(e),
                recommendation="Please try again or contact support",
                category='other'
            )

    def _scan_ports(self, scan):
        """Scan for open ports using nmap"""
        try:
            logger.info(f"Starting nmap scan for {scan.url}")
            nm = nmap.PortScanner()
            
            # Extract hostname from URL
            parsed_url = urlparse(scan.url)
            hostname = parsed_url.netloc
            
            # Scan common ports only to avoid timeouts
            nm.scan(hostname, '21-23,25,53,80,110,443,993,995', arguments='-sT -T4')
            
            for host in nm.all_hosts():
                for protocol in nm[host].all_protocols():
                    ports = nm[host][protocol].keys()
                    for port in ports:
                        state = nm[host][protocol][port]['state']
                        if state == 'open':
                            logger.info(f"Found open port {port} on {host}")
                            
                            # Determine severity based on port
                            level = 'low'
                            if port in [21, 23, 25]:  # FTP, Telnet, SMTP
                                level = 'medium'
                            elif port == 22:  # SSH
                                level = 'low'
                                
                            Vulnerability.objects.create(
                                scan=scan,
                                name=f"Open Port {port}",
                                description=f"Port {port} ({protocol.upper()}) is open and accessible",
                                level=level,
                                details=f"State: {state}, Service: {nm[host][protocol][port].get('name', 'unknown')}",
                                recommendation=f"Ensure port {port} is necessary and properly secured. Consider firewall restrictions.",
                                category='openPorts'
                            )
        except Exception as e:
            logger.warning(f"Port scan failed for {scan.url}: {str(e)}")
            # Don't fail the entire scan for port scan issues

    def _analyze_website(self, scan):
        """Analyze website for security issues"""
        try:
            logger.info(f"Starting website analysis for {scan.url}")
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(scan.url, headers=headers, timeout=10, verify=False)
            response.raise_for_status()
            
            # Check security headers
            self._check_security_headers(scan, response.headers)
            
            # Analyze HTML content
            soup = BeautifulSoup(response.text, 'html.parser')
            self._analyze_html_content(scan, soup)
            
        except requests.RequestException as e:
            logger.warning(f"Website analysis failed for {scan.url}: {str(e)}")
            Vulnerability.objects.create(
                scan=scan,
                name="Website Analysis Failed",
                description="Could not analyze website security",
                level='none',
                details=str(e),
                recommendation="Check if the website is accessible and try again",
                category='other'
            )

    def _check_security_headers(self, scan, headers):
        """Check for missing security headers"""
        security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': None,
            'Content-Security-Policy': None,
        }
        
        for header, expected_value in security_headers.items():
            if header not in headers:
                Vulnerability.objects.create(
                    scan=scan,
                    name=f"Missing Security Header: {header}",
                    description=f"The {header} security header is not set",
                    level='medium' if header == 'Content-Security-Policy' else 'low',
                    details=f"Header '{header}' was not found in the response",
                    recommendation=f"Add the {header} header to improve security",
                    category='other'
                )

    def _analyze_html_content(self, scan, soup):
        """Analyze HTML content for potential issues"""
        # Check for forms without CSRF protection (basic check)
        forms = soup.find_all('form')
        for form in forms:
            if not form.find('input', {'name': 'csrfmiddlewaretoken'}) and not form.find('input', {'name': '_token'}):
                Vulnerability.objects.create(
                    scan=scan,
                    name="Form without CSRF Protection",
                    description="Found form that may lack CSRF protection",
                    level='medium',
                    details=f"Form action: {form.get('action', 'No action specified')}",
                    recommendation="Implement CSRF protection for all forms",
                    category='other'
                )

        # Check for inline scripts (potential XSS risk)
        inline_scripts = soup.find_all('script', string=True)
        if inline_scripts:
            Vulnerability.objects.create(
                scan=scan,
                name="Inline JavaScript Detected",
                description="Found inline JavaScript which may pose XSS risks",
                level='low',
                details=f"Found {len(inline_scripts)} inline script tags",
                recommendation="Consider using Content Security Policy and external script files",
                category='xss'
            )