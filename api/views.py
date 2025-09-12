import logging
import subprocess
import tempfile
import os
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from .models import Scan, Vulnerability
from .serializers import ScanSerializer
import nmap
from bs4 import BeautifulSoup
import requests
from django.utils import timezone
from django.conf import settings
import threading
from urllib.parse import urlparse, urljoin
import re
import time
import random
from django.core.cache import cache
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

logger = logging.getLogger(__name__)

class SimpleCaptchaView(APIView):
    """Simple math captcha for request validation"""
    permission_classes = [AllowAny]
    
    def get(self, request):
        """Generate a simple math captcha"""
        num1 = random.randint(1, 20)
        num2 = random.randint(1, 20)
        operation = random.choice(['+', '-', '*'])
        
        if operation == '+':
            answer = num1 + num2
            question = f"{num1} + {num2} = ?"
        elif operation == '-':
            answer = num1 - num2 if num1 > num2 else num2 - num1
            question = f"{max(num1, num2)} - {min(num1, num2)} = ?"
        else:  # multiplication
            num1 = random.randint(1, 10)  # Smaller numbers for multiplication
            num2 = random.randint(1, 10)
            answer = num1 * num2
            question = f"{num1} × {num2} = ?"
        
        # Store answer in cache with unique token
        token = f"captcha_{int(time.time())}_{random.randint(1000, 9999)}"
        cache.set(token, answer, timeout=300)  # 5 minutes expiry
        
        return Response({
            'token': token,
            'question': question
        })

@method_decorator(csrf_exempt, name='dispatch')
class ScanView(APIView):
    def post(self, request):
        """Start a new security scan with captcha validation"""
        logger.info("Received POST request to /api/scan/")
        
        url = request.data.get('url')
        captcha_token = request.data.get('captcha_token')
        captcha_answer = request.data.get('captcha_answer')
        
        logger.info(f"URL: {url}")
        
        if not url:
            logger.error("URL is required")
            return Response({'error': 'URL is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Validate captcha for non-authenticated users
        if not request.user.is_authenticated:
            if not captcha_token or not captcha_answer:
                return Response({'error': 'Captcha validation required'}, status=status.HTTP_400_BAD_REQUEST)
            
            cached_answer = cache.get(captcha_token)
            if cached_answer is None:
                return Response({'error': 'Captcha expired or invalid'}, status=status.HTTP_400_BAD_REQUEST)
            
            try:
                if int(captcha_answer) != cached_answer:
                    return Response({'error': 'Incorrect captcha answer'}, status=status.HTTP_400_BAD_REQUEST)
            except (ValueError, TypeError):
                return Response({'error': 'Invalid captcha answer format'}, status=status.HTTP_400_BAD_REQUEST)
            
            # Delete used captcha
            cache.delete(captcha_token)

        # Rate limiting for non-authenticated users
        if not request.user.is_authenticated:
            client_ip = self._get_client_ip(request)
            rate_limit_key = f"scan_rate_{client_ip}"
            recent_scans = cache.get(rate_limit_key, 0)
            
            if recent_scans >= 5:  # Max 5 scans per hour for non-authenticated users
                return Response({
                    'error': 'Rate limit exceeded. Please wait before starting another scan.'
                }, status=status.HTTP_429_TOO_MANY_REQUESTS)
            
            cache.set(rate_limit_key, recent_scans + 1, timeout=3600)  # 1 hour

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
        scan_id = str(int(timezone.now().timestamp() * 1000))
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

    def _get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def _perform_scan(self, scan):
        """Perform the actual security scan in background"""
        try:
            logger.info(f"Starting background scan for {scan.url}")
            
            # Step 1: Basic reconnaissance
            scan.progress = 10
            scan.save()
            
            # Step 2: Port scanning with nmap
            self._scan_ports(scan)
            scan.progress = 30
            scan.save()
            
            # Step 3: Web application analysis
            self._analyze_website(scan)
            scan.progress = 50
            scan.save()
            
            # Step 4: SQL Injection testing
            self._test_sql_injection(scan)
            scan.progress = 70
            scan.save()
            
            # Step 5: XSS testing
            self._test_xss_vulnerabilities(scan)
            scan.progress = 90
            scan.save()
            
            # Step 6: Complete
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
            nm.scan(hostname, '21-23,25,53,80,110,443,993,995,8080,8443', arguments='-sT -T4 --host-timeout 30s')
            
            for host in nm.all_hosts():
                for protocol in nm[host].all_protocols():
                    ports = nm[host][protocol].keys()
                    for port in ports:
                        state = nm[host][protocol][port]['state']
                        if state == 'open':
                            logger.info(f"Found open port {port} on {host}")
                            
                            # Determine severity based on port
                            level = 'low'
                            service_name = nm[host][protocol][port].get('name', 'unknown')
                            
                            if port in [21, 23, 25]:  # FTP, Telnet, SMTP
                                level = 'medium'
                            elif port == 22:  # SSH
                                level = 'low'
                            elif port in [80, 443, 8080, 8443]:  # Web services
                                level = 'low'
                                
                            Vulnerability.objects.create(
                                scan=scan,
                                name=f"Open Port {port}",
                                description=f"Port {port} ({protocol.upper()}) is open and accessible",
                                level=level,
                                details=f"State: {state}, Service: {service_name}",
                                recommendation=f"Ensure port {port} is necessary and properly secured. Consider firewall restrictions.",
                                category='openPorts'
                            )
        except Exception as e:
            logger.warning(f"Port scan failed for {scan.url}: {str(e)}")

    def _test_sql_injection(self, scan):
        """Test for SQL injection vulnerabilities"""
        try:
            logger.info(f"Starting SQL injection testing for {scan.url}")
            
            # Get forms from the website
            response = requests.get(scan.url, timeout=10, verify=True)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            sql_payloads = [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' OR '1'='1' /*",
                "admin'--",
                "admin'/*",
                "' OR 1=1--",
                "' UNION SELECT NULL--",
                "1' AND '1'='1",
                "1' AND '1'='2"
            ]
            
            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                
                # Get form inputs
                inputs = form.find_all(['input', 'textarea', 'select'])
                form_data = {}
                
                for input_tag in inputs:
                    input_name = input_tag.get('name')
                    input_type = input_tag.get('type', 'text')
                    
                    if input_name and input_type not in ['submit', 'button', 'reset']:
                        form_data[input_name] = 'test'
                
                if not form_data:
                    continue
                
                # Test SQL injection payloads
                for payload in sql_payloads[:3]:  # Limit payloads to avoid too many requests
                    test_data = form_data.copy()
                    # Test payload in first text field
                    first_field = next(iter(test_data.keys()))
                    test_data[first_field] = payload
                    
                    try:
                        target_url = urljoin(scan.url, action) if action else scan.url
                        
                        if method == 'post':
                            test_response = requests.post(target_url, data=test_data, timeout=5, verify=True)
                        else:
                            test_response = requests.get(target_url, params=test_data, timeout=5, verify=True)
                        
                        # Look for SQL error patterns
                        error_patterns = [
                            r'mysql_fetch_array\(\)',
                            r'ORA-[0-9]+',
                            r'Microsoft OLE DB Provider',
                            r'SQLSTATE\[\w+\]',
                            r'PostgreSQL.*ERROR',
                            r'Warning.*mysql_.*',
                            r'valid MySQL result',
                            r'MySqlClient\.',
                        ]
                        
                        for pattern in error_patterns:
                            if re.search(pattern, test_response.text, re.IGNORECASE):
                                Vulnerability.objects.create(
                                    scan=scan,
                                    name="Potential SQL Injection",
                                    description=f"SQL injection vulnerability detected in form",
                                    level='high',
                                    details=f"Form action: {action}, Method: {method}, Payload: {payload}",
                                    recommendation="Use parameterized queries and input validation",
                                    category='sqlInjection'
                                )
                                logger.info(f"SQL injection found in form: {action}")
                                break
                    
                    except requests.RequestException:
                        continue
                        
        except Exception as e:
            logger.warning(f"SQL injection testing failed for {scan.url}: {str(e)}")

    def _test_xss_vulnerabilities(self, scan):
        """Test for XSS vulnerabilities"""
        try:
            logger.info(f"Starting XSS testing for {scan.url}")
            
            response = requests.get(scan.url, timeout=10, verify=True)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            xss_payloads = [
                "<script>alert('XSS')</script>",
                "'><script>alert('XSS')</script>",
                "\"><script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')"
            ]
            
            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                
                inputs = form.find_all(['input', 'textarea', 'select'])
                form_data = {}
                
                for input_tag in inputs:
                    input_name = input_tag.get('name')
                    input_type = input_tag.get('type', 'text')
                    
                    if input_name and input_type not in ['submit', 'button', 'reset']:
                        form_data[input_name] = 'test'
                
                if not form_data:
                    continue
                
                # Test XSS payloads
                for payload in xss_payloads[:2]:  # Limit payloads
                    test_data = form_data.copy()
                    first_field = next(iter(test_data.keys()))
                    test_data[first_field] = payload
                    
                    try:
                        target_url = urljoin(scan.url, action) if action else scan.url
                        
                        if method == 'post':
                            test_response = requests.post(target_url, data=test_data, timeout=5, verify=True)
                        else:
                            test_response = requests.get(target_url, params=test_data, timeout=5, verify=True)
                        
                        # Check if payload is reflected unescaped
                        if payload in test_response.text:
                            Vulnerability.objects.create(
                                scan=scan,
                                name="Potential XSS Vulnerability",
                                description="Cross-site scripting vulnerability detected",
                                level='high',
                                details=f"Reflected XSS in form. Action: {action}, Method: {method}",
                                recommendation="Implement proper input sanitization and output encoding",
                                category='xss'
                            )
                            logger.info(f"XSS vulnerability found in form: {action}")
                            break
                    
                    except requests.RequestException:
                        continue
                        
        except Exception as e:
            logger.warning(f"XSS testing failed for {scan.url}: {str(e)}")

    def _analyze_website(self, scan):
        """Analyze website for security issues"""
        try:
            logger.info(f"Starting website analysis for {scan.url}")
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            response = requests.get(scan.url, headers=headers, timeout=15, verify=True)
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
            'X-Content-Type-Options': {
                'expected': 'nosniff',
                'level': 'medium',
                'description': 'Prevents MIME type sniffing attacks'
            },
            'X-Frame-Options': {
                'expected': ['DENY', 'SAMEORIGIN'],
                'level': 'medium',
                'description': 'Prevents clickjacking attacks'
            },
            'X-XSS-Protection': {
                'expected': '1; mode=block',
                'level': 'low',
                'description': 'Enables browser XSS filtering'
            },
            'Strict-Transport-Security': {
                'expected': None,
                'level': 'medium',
                'description': 'Enforces HTTPS connections'
            },
            'Content-Security-Policy': {
                'expected': None,
                'level': 'high',
                'description': 'Prevents various injection attacks'
            },
        }
        
        for header, config in security_headers.items():
            if header not in headers:
                Vulnerability.objects.create(
                    scan=scan,
                    name=f"Missing Security Header: {header}",
                    description=f"The {header} security header is not set - {config['description']}",
                    level=config['level'],
                    details=f"Header '{header}' was not found in the response",
                    recommendation=f"Add the {header} header to improve security",
                    category='other'
                )

    def _analyze_html_content(self, scan, soup):
        """Analyze HTML content for potential issues"""
        # Check for forms without CSRF protection
        forms = soup.find_all('form')
        for form in forms:
            method = form.get('method', 'get').lower()
            if method == 'post':
                csrf_tokens = form.find_all('input', {'name': re.compile(r'.*csrf.*|.*token.*', re.I)})
                if not csrf_tokens:
                    Vulnerability.objects.create(
                        scan=scan,
                        name="Form without CSRF Protection",
                        description="Found POST form that may lack CSRF protection",
                        level='medium',
                        details=f"Form action: {form.get('action', 'No action specified')}",
                        recommendation="Implement CSRF protection for all forms",
                        category='other'
                    )

        # Check for inline scripts
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
            
        # Check for external scripts without integrity checks
        external_scripts = soup.find_all('script', src=True)
        for script in external_scripts:
            src = script.get('src', '')
            if src.startswith(('http://', 'https://')) and not script.get('integrity'):
                if not src.startswith(urlparse(scan.url).scheme + '://' + urlparse(scan.url).netloc):
                    Vulnerability.objects.create(
                        scan=scan,
                        name="External Script without Integrity Check",
                        description="External script loaded without integrity verification",
                        level='medium',
                        details=f"Script source: {src}",
                        recommendation="Add integrity attributes to external scripts",
                        category='other'
                    )