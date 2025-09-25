import logging
import subprocess
import tempfile
import os
import json
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
            num1 = random.randint(1, 10)
            num2 = random.randint(1, 10)
            answer = num1 * num2
            question = f"{num1} × {num2} = ?"
        
        token = f"captcha_{int(time.time())}_{random.randint(1000, 9999)}"
        cache.set(token, answer, timeout=300)
        
        return Response({
            'token': token,
            'question': question
        })

@method_decorator(csrf_exempt, name='dispatch')
class ScanView(APIView):
    permission_classes = [AllowAny]
    
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
            
            cache.delete(captcha_token)

        # Rate limiting for non-authenticated users
        if not request.user.is_authenticated:
            client_ip = self._get_client_ip(request)
            rate_limit_key = f"scan_rate_{client_ip}"
            recent_scans = cache.get(rate_limit_key, 0)
            
            if recent_scans >= 5:
                return Response({
                    'error': 'Rate limit exceeded. Please wait before starting another scan.'
                }, status=status.HTTP_429_TOO_MANY_REQUESTS)
            
            cache.set(rate_limit_key, recent_scans + 1, timeout=3600)

        # Validate URL format
        try:
            parsed_url = urlparse(url)
            if not parsed_url.scheme:
                url = f"https://{url}"
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
            scan.progress = 25
            scan.save()
            
            # Step 3: Web application analysis
            self._analyze_website(scan)
            scan.progress = 40
            scan.save()
            
            # Step 4: Enhanced SQL Injection testing with sqlmap
            self._test_sql_injection_with_sqlmap(scan)
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
            
            Vulnerability.objects.create(
                scan=scan,
                name="Scan Error",
                description="An error occurred during scanning",
                level='none',
                details=str(e),
                recommendation="Please try again or contact support",
                category='other'
            )

    def _check_sqlmap_installation(self):
        """Check if sqlmap is installed and accessible - Windows optimized"""
        try:
            result = subprocess.run(['sqlmap', '--version'], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=15,
                                  cwd=settings.BASE_DIR,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
            if result.returncode == 0:
                logger.info(f"SQLMap found: {result.stdout.strip()}")
                return True
            else:
                logger.warning("SQLMap not found or not working properly")
                return False
        except subprocess.TimeoutExpired:
            logger.warning("SQLMap test timed out - assuming it works")
            return True  # Assume it works despite timeout
        except Exception as e:
         logger.error(f"SQLMap check failed: {str(e)}")
        return False

    def _test_sql_injection_with_sqlmap(self, scan):
        """Enhanced SQL injection testing using sqlmap"""
        logger.info(f"Starting SQLMap SQL injection testing for {scan.url}")
        
        # Check if sqlmap is available
        if not self._check_sqlmap_installation():
            logger.warning("SQLMap not available, falling back to basic SQL injection testing")
            self._test_sql_injection_basic(scan)
            return
        
        try:
            # Get forms and parameters from the website
            response = requests.get(scan.url, timeout=10, verify=True)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            # Test each form with sqlmap
            for form_index, form in enumerate(forms[:3]):  # Limit to first 3 forms
                self._run_sqlmap_on_form(scan, form, form_index)
            
            # Test URL parameters if any
            parsed_url = urlparse(scan.url)
            if parsed_url.query:
                self._run_sqlmap_on_url(scan, scan.url)
                
        except Exception as e:
            logger.error(f"SQLMap testing failed for {scan.url}: {str(e)}")
            # Fallback to basic testing
            self._test_sql_injection_basic(scan)

    def _run_sqlmap_on_form(self, scan, form, form_index):
        """Run sqlmap on a specific form"""
        try:
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            
            if not action:
                target_url = scan.url
            else:
                target_url = urljoin(scan.url, action)
            
            # Build form data string for sqlmap
            inputs = form.find_all(['input', 'textarea', 'select'])
            form_data_parts = []
            
            for input_tag in inputs:
                input_name = input_tag.get('name')
                input_type = input_tag.get('type', 'text')
                
                if input_name and input_type not in ['submit', 'button', 'reset']:
                    form_data_parts.append(f"{input_name}=test")
            
            if not form_data_parts:
                return
            
            form_data = "&".join(form_data_parts)
            
            # Create temporary file for sqlmap output
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
                temp_file_path = temp_file.name
            
            try:
                # Build sqlmap command
                cmd = [
                    'sqlmap',
                    '-u', target_url,
                    '--batch',  # Never ask for user input
                    '--smart',  # Use smart heuristics
                    '--level', '1',  # Test level (1-5)
                    '--risk', '1',   # Risk level (1-3)
                    '--timeout', '30',
                    '--retries', '1',
                    '--threads', '2',
                    '--output-dir', os.path.dirname(temp_file_path),
                    '--flush-session',  # Flush session files
                    '--disable-coloring',  # Disable colored output
                ]
                
                # Add form data if POST method
                if method.lower() == 'post' and form_data:
                    cmd.extend(['--data', form_data])
                
                # Add specific tests
                cmd.extend([
                    '--technique', 'BEUST',  # Test all techniques
                    '--dbms', 'MySQL,PostgreSQL,SQLite,Oracle,MSSQL',
                ])
                
                # Run sqlmap with timeout
                logger.info(f"Running SQLMap command: {' '.join(cmd)}")
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=120,  # 2 minutes timeout
                    cwd=tempfile.gettempdir()
                )
                
                # Parse results
                self._parse_sqlmap_results(scan, result, target_url, f"Form {form_index + 1}")
                
            finally:
                # Clean up temporary file
                try:
                    if os.path.exists(temp_file_path):
                        os.unlink(temp_file_path)
                except OSError:
                    pass
                    
        except subprocess.TimeoutExpired:
            logger.warning(f"SQLMap timeout for form in {scan.url}")
            Vulnerability.objects.create(
                scan=scan,
                name="SQL Injection Test Timeout",
                description="SQLMap testing timed out for this form",
                level='none',
                details=f"Form action: {action}, Method: {method}",
                recommendation="Consider manual testing for this form",
                category='sqlInjection'
            )
        except Exception as e:
            logger.error(f"SQLMap form testing failed: {str(e)}")

    def _run_sqlmap_on_url(self, scan, target_url):
        """Run sqlmap on URL with parameters"""
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
                temp_file_path = temp_file.name
            
            try:
                cmd = [
                    'sqlmap',
                    '-u', target_url,
                    '--batch',
                    '--smart',
                    '--level', '1',
                    '--risk', '1',
                    '--timeout', '30',
                    '--retries', '1',
                    '--threads', '2',
                    '--output-dir', os.path.dirname(temp_file_path),
                    '--flush-session',
                    '--disable-coloring',
                    '--technique', 'BEUST',
                ]
                
                logger.info(f"Running SQLMap on URL: {target_url}")
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=120,
                    cwd=tempfile.gettempdir()
                )
                
                self._parse_sqlmap_results(scan, result, target_url, "URL Parameters")
                
            finally:
                try:
                    if os.path.exists(temp_file_path):
                        os.unlink(temp_file_path)
                except OSError:
                    pass
                    
        except subprocess.TimeoutExpired:
            logger.warning(f"SQLMap timeout for URL {target_url}")
        except Exception as e:
            logger.error(f"SQLMap URL testing failed: {str(e)}")

    def _parse_sqlmap_results(self, scan, result, target_url, test_location):
        """Parse sqlmap output and create vulnerability records"""
        try:
            output = result.stdout + result.stderr
            
            # Check for SQL injection indicators in output
            vulnerability_indicators = [
                'Parameter:',
                'Type:',
                'Title:',
                'Payload:',
                'is vulnerable',
                'sqlmap identified',
                'injection point',
                'back-end DBMS'
            ]
            
            is_vulnerable = any(indicator in output.lower() for indicator in 
                             ['is vulnerable', 'injection point', 'sqlmap identified'])
            
            if is_vulnerable:
                # Extract vulnerability details
                lines = output.split('\n')
                vulnerability_details = []
                payload = "Not specified"
                db_type = "Unknown"
                injection_type = "Unknown"
                
                for i, line in enumerate(lines):
                    line_lower = line.lower().strip()
                    
                    if 'parameter:' in line_lower:
                        vulnerability_details.append(line.strip())
                    elif 'type:' in line_lower:
                        injection_type = line.split(':', 1)[1].strip()
                        vulnerability_details.append(line.strip())
                    elif 'title:' in line_lower:
                        vulnerability_details.append(line.strip())
                    elif 'payload:' in line_lower:
                        payload = line.split(':', 1)[1].strip() if ':' in line else "Not specified"
                        vulnerability_details.append(line.strip())
                    elif 'back-end dbms:' in line_lower:
                        db_type = line.split(':', 1)[1].strip()
                        vulnerability_details.append(line.strip())
                
                # Determine severity based on injection type
                severity = 'high'
                if 'boolean' in injection_type.lower() or 'time' in injection_type.lower():
                    severity = 'high'
                elif 'error' in injection_type.lower():
                    severity = 'high'
                else:
                    severity = 'medium'
                
                Vulnerability.objects.create(
                    scan=scan,
                    name=f"SQL Injection Vulnerability ({test_location})",
                    description=f"SQLMap detected SQL injection vulnerability in {test_location}",
                    level=severity,
                    details=f"URL: {target_url}\nInjection Type: {injection_type}\nDatabase: {db_type}\nPayload: {payload}\n\nFull Details:\n" + "\n".join(vulnerability_details),
                    recommendation="Use parameterized queries/prepared statements, implement input validation, and sanitize user inputs. Consider using an ORM that handles SQL injection prevention.",
                    category='sqlInjection'
                )
                
                logger.info(f"SQL injection found by SQLMap in {test_location}: {target_url}")
                
            else:
                # Check for potential false negatives or interesting findings
                if 'heuristic' in output.lower() or 'appears to be' in output.lower():
                    Vulnerability.objects.create(
                        scan=scan,
                        name=f"Potential SQL Injection ({test_location})",
                        description="SQLMap detected potential SQL injection indicators",
                        level='low',
                        details=f"URL: {target_url}\nSQLMap found potential indicators but couldn't confirm vulnerability.",
                        recommendation="Manual verification recommended. Review input validation and consider penetration testing.",
                        category='sqlInjection'
                    )
                
        except Exception as e:
            logger.error(f"Error parsing SQLMap results: {str(e)}")

    def _test_sql_injection_basic(self, scan):
        """Basic SQL injection testing (fallback when sqlmap is not available)"""
        try:
            logger.info(f"Starting basic SQL injection testing for {scan.url}")
            
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
                
                inputs = form.find_all(['input', 'textarea', 'select'])
                form_data = {}
                
                for input_tag in inputs:
                    input_name = input_tag.get('name')
                    input_type = input_tag.get('type', 'text')
                    
                    if input_name and input_type not in ['submit', 'button', 'reset']:
                        form_data[input_name] = 'test'
                
                if not form_data:
                    continue
                
                for payload in sql_payloads[:3]:
                    test_data = form_data.copy()
                    first_field = next(iter(test_data.keys()))
                    test_data[first_field] = payload
                    
                    try:
                        target_url = urljoin(scan.url, action) if action else scan.url
                        
                        if method == 'post':
                            test_response = requests.post(target_url, data=test_data, timeout=5, verify=True)
                        else:
                            test_response = requests.get(target_url, params=test_data, timeout=5, verify=True)
                        
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
                                    name="Potential SQL Injection (Basic Test)",
                                    description=f"Basic SQL injection test detected potential vulnerability",
                                    level='medium',
                                    details=f"Form action: {action}, Method: {method}, Payload: {payload}",
                                    recommendation="Use parameterized queries and input validation. Consider professional security testing.",
                                    category='sqlInjection'
                                )
                                logger.info(f"Basic SQL injection test found potential vulnerability: {action}")
                                break
                    
                    except requests.RequestException:
                        continue
                        
        except Exception as e:
            logger.warning(f"Basic SQL injection testing failed for {scan.url}: {str(e)}")

    # Keep existing methods unchanged
    def _scan_ports(self, scan):
        """Scan for open ports using nmap"""
        try:
            logger.info(f"Starting nmap scan for {scan.url}")
            nm = nmap.PortScanner()
            
            parsed_url = urlparse(scan.url)
            hostname = parsed_url.netloc
            
            nm.scan(hostname, '21-23,25,53,80,110,443,993,995,8080,8443', arguments='-sT -T4 --host-timeout 30s')
            
            for host in nm.all_hosts():
                for protocol in nm[host].all_protocols():
                    ports = nm[host][protocol].keys()
                    for port in ports:
                        state = nm[host][protocol][port]['state']
                        if state == 'open':
                            logger.info(f"Found open port {port} on {host}")
                            
                            level = 'low'
                            service_name = nm[host][protocol][port].get('name', 'unknown')
                            
                            if port in [21, 23, 25]:
                                level = 'medium'
                            elif port == 22:
                                level = 'low'
                            elif port in [80, 443, 8080, 8443]:
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
                
                for payload in xss_payloads[:2]:
                    test_data = form_data.copy()
                    first_field = next(iter(test_data.keys()))
                    test_data[first_field] = payload
                    
                    try:
                        target_url = urljoin(scan.url, action) if action else scan.url
                        
                        if method == 'post':
                            test_response = requests.post(target_url, data=test_data, timeout=5, verify=True)
                        else:
                            test_response = requests.get(target_url, params=test_data, timeout=5, verify=True)
                        
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
            
            self._check_security_headers(scan, response.headers)
            
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