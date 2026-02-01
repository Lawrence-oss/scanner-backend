import logging
import subprocess
import sys
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
from urllib.parse import urlparse, urljoin, parse_qs
import re
import time
import random
import html
import urllib.parse
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

    MAX_SCAN_DURATION = 900  # 15 minutes total scan timeout (increased for thorough scanning)
    MAX_SQL_INJECTION_DURATION = 540  # 9 minutes for SQL injection phase (more time for deep testing)
    MAX_ENDPOINTS_TO_TEST = 25  # Test more endpoints for better coverage
    SQLMAP_TIMEOUT_PER_ENDPOINT = 60  # 60 seconds per endpoint (more time to find complex injections)
    CRAWL_TIMEOUT = 90  # 1.5 minutes for crawling phase (find more pages)

    # Comprehensive port list for security scanning
    SCAN_PORTS = (
        '21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,'  # Common services
        '1433,1521,3306,3389,5432,5900,6379,8080,8443,27017'      # Databases & admin
    )

    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.discovered_urls = set()
        self.tested_urls = set()
        self.tested_signatures = set()  # Track URL patterns to avoid duplicate testing
        self.scan_start_time = None
        self.sql_phase_start_time = None
    
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

    def _get_url_signature(self, url):
        """
        Generate a unique signature for a URL based on its structure and parameter names.
        This helps avoid testing the same endpoint multiple times with different parameter values.
        
        Example:
        - http://site.com/page.php?id=1&name=test
        - http://site.com/page.php?id=2&name=admin
        Both generate the same signature: "http://site.com/page.php:id,name"
        """
        parsed = urlparse(url)
        if parsed.query:
            param_names = sorted(parse_qs(parsed.query).keys())
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}:{','.join(param_names)}"
        else:
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    # ============================================================================
    # MAIN SCAN ORCHESTRATION WITH TIMEOUT CONTROLS
    # ============================================================================
    def _perform_scan(self, scan):
        """Perform the actual security scan in background WITH TIMEOUT"""
        try:
            logger.info(f"🚀 Starting background scan for {scan.url}")
            
            # START SCAN TIMER
            self.scan_start_time = time.time()
            
            # Reset tracking sets for this scan
            self.discovered_urls = set()
            self.tested_urls = set()
            self.tested_signatures = set()
            
            # Step 1: Basic reconnaissance
            scan.progress = 10
            scan.save()
            
            # Step 2: Port scanning with nmap (with timeout check)
            if self._check_scan_timeout():
                self._handle_scan_timeout(scan, "Port scanning")
                return
            
            self._scan_ports(scan)
            scan.progress = 25
            scan.save()
            
            # Step 3: Web application analysis (with timeout check)
            if self._check_scan_timeout():
                self._handle_scan_timeout(scan, "Website analysis")
                return
                
            self._analyze_website(scan)
            scan.progress = 40
            scan.save()
            
            # Step 4: SQL Injection testing (with timeout check)
            if self._check_scan_timeout():
                self._handle_scan_timeout(scan, "SQL injection testing")
                return
                
            self._test_sql_injection_with_sqlmap(scan)
            scan.progress = 70
            scan.save()
            
            # Step 5: XSS testing (with timeout check)
            if self._check_scan_timeout():
                self._handle_scan_timeout(scan, "XSS testing")
                return
                
            self._test_xss_vulnerabilities(scan)
            scan.progress = 90
            scan.save()
            
            # Step 6: Complete
            elapsed_time = time.time() - self.scan_start_time
            scan.status = 'completed'
            scan.progress = 100
            scan.save()
            logger.info(f"✅ Scan {scan.id} completed successfully in {elapsed_time:.1f} seconds ({elapsed_time/60:.1f} minutes)")
            
        except Exception as e:
            logger.error(f"❌ Scan {scan.id} failed: {str(e)}", exc_info=True)
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

    def _check_scan_timeout(self):
        """Check if total scan has exceeded maximum duration"""
        if self.scan_start_time is None:
            return False
        
        elapsed = time.time() - self.scan_start_time
        if elapsed > self.MAX_SCAN_DURATION:
            logger.warning(f"⏱️ Total scan timeout reached: {elapsed:.1f}s / {self.MAX_SCAN_DURATION}s")
            return True
        return False

    def _check_sql_phase_timeout(self):
        """Check if SQL injection phase has exceeded maximum duration"""
        if self.sql_phase_start_time is None:
            return False
        
        elapsed = time.time() - self.sql_phase_start_time
        if elapsed > self.MAX_SQL_INJECTION_DURATION:
            logger.warning(f"⏱️ SQL phase timeout reached: {elapsed:.1f}s / {self.MAX_SQL_INJECTION_DURATION}s")
            return True
        return False

    def _handle_scan_timeout(self, scan, phase_name):
        """Handle scan timeout gracefully"""
        elapsed = time.time() - self.scan_start_time
        logger.warning(f"⏱️ Scan timeout reached during {phase_name} ({elapsed:.1f}s / {self.MAX_SCAN_DURATION}s)")
        
        scan.status = 'completed'
        scan.progress = 100
        scan.save()
        
        Vulnerability.objects.create(
            scan=scan,
            name="⏱️ Scan Timeout - Partial Results",
            description=f"Scan exceeded maximum duration of {self.MAX_SCAN_DURATION}s during {phase_name}",
            level='none',
            details=f"Scan timed out after {elapsed:.1f} seconds ({elapsed/60:.1f} minutes).\n\nCompleted phases:\n✅ Phases before {phase_name}\n\n⚠️ Incomplete phases:\n❌ {phase_name} and subsequent tests\n\nNote: Partial results are still available for completed phases.",
            recommendation="For complete results, consider:\n- Testing specific endpoints manually\n- Running focused scans on individual pages\n- Increasing timeout limits if needed",
            category='other'
        )

    def _create_timeout_vulnerability(self, scan, test_name, phase):
        """Create a vulnerability entry for timeout"""
        Vulnerability.objects.create(
            scan=scan,
            name=f"⏱️ {test_name} Testing Timeout",
            description=f"{test_name} testing timed out during {phase}",
            level='none',
            details=f"Testing exceeded time limit of {self.MAX_SQL_INJECTION_DURATION}s.\n\nPartial results may be available above.\n\nConsider manual testing for complete coverage.",
            recommendation="Options:\n- Run focused scans on specific endpoints\n- Increase timeout limits in configuration\n- Use SQLMap directly for thorough testing",
            category='sqlInjection'
        )


    def _check_sqlmap_installation(self):
        """Check if sqlmap is installed and accessible - Windows optimized"""
        try:
            sqlmap_path = os.path.join(settings.BASE_DIR, 'sqlmap', 'sqlmap.py')
            
            if os.path.exists(sqlmap_path):
                cmd = [sys.executable, sqlmap_path, '--version']
                logger.info(f"Testing local SQLMap installation: {sqlmap_path}")
            else:
                cmd = ['sqlmap', '--version']
                logger.info("Testing system SQLMap installation")
            
            result = subprocess.run(
                cmd,
                capture_output=True, 
                text=True, 
                timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            
            if result.returncode == 0:
                logger.info(f"SQLMap working: {result.stdout.strip()}")
                return True
            else:
                logger.warning(f"SQLMap test failed with exit code: {result.returncode}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.warning("SQLMap test timed out - this is normal on Windows, assuming it works")
            return True
        except FileNotFoundError:
            logger.error("SQLMap executable not found")
            return False
        except Exception as e:
            logger.error(f"SQLMap check failed: {str(e)}")
            return False

    # ============================================================================
    # NEW: COMPREHENSIVE SITE CRAWLER
    # ============================================================================
    def _crawl_site(self, base_url, max_depth=3, max_urls=50):
        """Crawl the site to discover all endpoints WITH TIMEOUT"""
        logger.info(f"🕷️ Crawling {base_url} (max depth: {max_depth}, timeout: {self.CRAWL_TIMEOUT}s)")
        
        crawl_start = time.time()
        to_visit = [(base_url, 0)]
        visited = set()
        discovered_endpoints = []
        seen_endpoints = set()  # Track unique endpoint signatures
        
        while to_visit and len(discovered_endpoints) < max_urls:
            # Check crawl timeout
            if time.time() - crawl_start > self.CRAWL_TIMEOUT:
                logger.warning(f"⏱️ Crawling timeout reached ({self.CRAWL_TIMEOUT}s) - stopping with {len(discovered_endpoints)} endpoints")
                break
            
            current_url, depth = to_visit.pop(0)
            
            if current_url in visited or depth > max_depth:
                continue
                
            visited.add(current_url)
            
            try:
                # Skip dangerous URLs
                skip_patterns = ['logout', 'signout', 'delete', 'remove', 'admin/delete']
                if any(pattern in current_url.lower() for pattern in skip_patterns):
                    logger.debug(f"⏭️ Skipping: {current_url}")
                    continue
                
                # Quick timeout for individual page requests
                # Try with SSL verification first, fall back to unverified if it fails
                try:
                    response = requests.get(current_url, timeout=5, verify=True)
                except requests.exceptions.SSLError:
                    logger.warning(f"SSL verification failed for {current_url}, retrying without verification")
                    response = requests.get(current_url, timeout=5, verify=False)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Find all forms on this page
                forms = soup.find_all('form')
                for form in forms:
                    action = form.get('action', '')
                    form_url = urljoin(current_url, action) if action else current_url
                    
                    # Create unique signature for this form (URL + method)
                    form_signature = f"form:{form_url}:{form.get('method', 'get').lower()}"
                    
                    if form_signature not in seen_endpoints:
                        seen_endpoints.add(form_signature)
                        discovered_endpoints.append({
                            'type': 'form',
                            'url': form_url,
                            'method': form.get('method', 'get').lower(),
                            'page_url': current_url
                        })
                
                # Find all links with parameters
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    full_url = urljoin(current_url, href)
                    
                    # Only follow links from the same domain
                    if urlparse(full_url).netloc == urlparse(base_url).netloc:
                        # Check if URL has parameters
                        parsed = urlparse(full_url)
                        if parsed.query:
                            # Create unique signature based on URL path and parameter names (not values)
                            param_names = sorted(parse_qs(parsed.query).keys())
                            url_signature = f"url_params:{parsed.scheme}://{parsed.netloc}{parsed.path}:{','.join(param_names)}"
                            
                            if url_signature not in seen_endpoints:
                                seen_endpoints.add(url_signature)
                                discovered_endpoints.append({
                                    'type': 'url_params',
                                    'url': full_url,
                                    'page_url': current_url
                                })
                        
                        # Add to crawl queue if within depth limit
                        if depth < max_depth:
                            to_visit.append((full_url, depth + 1))
                
                logger.debug(f"✓ Crawled: {current_url} (depth {depth}) - {len(discovered_endpoints)} endpoints total")
                
            except Exception as e:
                logger.warning(f"⚠️ Error crawling {current_url}: {str(e)}")
                continue
        
        elapsed = time.time() - crawl_start
        logger.info(f"🎯 Crawling complete in {elapsed:.1f}s - Discovered {len(discovered_endpoints)} unique endpoints")
        return discovered_endpoints

    # ============================================================================
    # COMPREHENSIVE SQL INJECTION TESTING WITH TIMEOUT
    # ============================================================================
    def _test_sql_injection_with_sqlmap(self, scan):
        """Run SQLMap on ALL discovered endpoints WITH TIMEOUT CONTROLS"""
        logger.info(f"🔍 Starting comprehensive SQL injection testing (max duration: {self.MAX_SQL_INJECTION_DURATION}s)")
        
        # START SQL PHASE TIMER
        self.sql_phase_start_time = time.time()
        
        if not self._check_sqlmap_installation():
            logger.warning("⚠️ SQLMap not available, falling back to basic testing")
            self._test_sql_injection_basic(scan)
            return

        # Phase 1: Crawl to discover endpoints
        logger.info("📋 Phase 1: Discovering all endpoints...")
        endpoints = self._crawl_site(scan.url, max_depth=2, max_urls=30)
        
        # Check if crawling took too long
        if self._check_sql_phase_timeout():
            logger.warning("⏱️ SQL phase timeout during crawling")
            self._create_timeout_vulnerability(scan, "SQL Injection", "crawling")
            return
        
        if not endpoints:
            logger.warning("⚠️ No endpoints discovered, testing base URL only")
            self._test_single_url_with_sqlmap(scan, scan.url, "Base URL")
            return
        
        # Phase 2: Test discovered endpoints
        logger.info(f"🎯 Phase 2: Testing up to {self.MAX_ENDPOINTS_TO_TEST} endpoints with SQLMap")
        
        tested_count = 0
        vulnerable_count = 0
        tested_signatures = set()  # Track tested URL patterns to avoid duplicates
        
        for idx, endpoint in enumerate(endpoints, 1):
            # Check SQL phase timeout
            if self._check_sql_phase_timeout():
                logger.warning(f"⏱️ SQL phase timeout after testing {tested_count} endpoints")
                self._create_timeout_vulnerability(
                    scan, 
                    "SQL Injection", 
                    f"testing (completed {tested_count}/{len(endpoints)} endpoints)"
                )
                break
            
            # Check endpoint limit
            if tested_count >= self.MAX_ENDPOINTS_TO_TEST:
                logger.info(f"⚠️ Reached testing limit of {self.MAX_ENDPOINTS_TO_TEST} endpoints")
                break
            
            endpoint_url = endpoint['url']
            endpoint_type = endpoint['type']
            
            # Create unique signature based on URL structure and parameter names, not values
            endpoint_signature = self._get_url_signature(endpoint_url)
            
            # Skip if we've already tested this URL pattern
            if endpoint_signature in tested_signatures:
                logger.debug(f"⏭️ Skipping duplicate pattern: {endpoint_url}")
                continue
            
            tested_signatures.add(endpoint_signature)
            tested_count += 1
            
            logger.info(f"🧪 Testing endpoint {tested_count}/{min(len(endpoints), self.MAX_ENDPOINTS_TO_TEST)}: {endpoint_url}")
            
            # Test with SQLMap
            is_vulnerable = self._test_single_url_with_sqlmap(
                scan, 
                endpoint_url, 
                f"{endpoint_type.upper()} on {endpoint.get('page_url', 'N/A')}"
            )
            
            if is_vulnerable:
                vulnerable_count += 1
                logger.info(f"🚨 VULNERABLE: {endpoint_url}")
        
        # Calculate elapsed time
        elapsed = time.time() - self.sql_phase_start_time
        logger.info(f"✅ SQL injection testing complete in {elapsed:.1f}s ({elapsed/60:.1f} minutes)")
        logger.info(f"📊 Results: Tested {tested_count} endpoints, found {vulnerable_count} vulnerabilities")
        
        # Create summary vulnerability
        Vulnerability.objects.create(
            scan=scan,
            name="📊 SQL Injection Scan Summary",
            description=f"Comprehensive SQL injection scan completed in {elapsed:.1f} seconds ({elapsed/60:.1f} minutes)",
            level='none' if vulnerable_count == 0 else 'info',
            details=f"Discovered endpoints: {len(endpoints)}\nTested endpoints: {tested_count}\nVulnerable endpoints: {vulnerable_count}\nTime elapsed: {elapsed:.1f}s ({elapsed/60:.1f} minutes)\n\n{'✅ No SQL injection vulnerabilities found!' if vulnerable_count == 0 else '⚠️ SQL injection vulnerabilities detected - see detailed reports above.'}",
            recommendation="Review all identified vulnerabilities and implement proper input validation." if vulnerable_count > 0 else "Continue monitoring and testing regularly.",
            category='sqlInjection'
        )

    # ============================================================================
    # SINGLE URL SQLMAP TEST WITH OPTIMIZED TIMEOUT
    # ============================================================================
    def _test_single_url_with_sqlmap(self, scan, url, test_location):
        """Test a single URL/endpoint with SQLMap - OPTIMIZED FOR SPEED"""
        try:
            # Check if we're running out of time before even starting
            if self._check_sql_phase_timeout():
                logger.warning(f"⏱️ Skipping {url} - SQL phase timeout imminent")
                return False
            
            sqlmap_path = os.path.join(settings.BASE_DIR, 'sqlmap', 'sqlmap.py')
            if os.path.exists(sqlmap_path):
                cmd = [sys.executable, sqlmap_path]
            else:
                cmd = ['sqlmap']

            # Check if URL has parameters or if we should use --forms
            parsed_url = urlparse(url)
            has_params = bool(parsed_url.query)
            
            cmd.extend([
                '-u', url,
                '--batch',                    # Non-interactive mode
                '--smart',                    # Smart mode - skip obvious non-injectables
                '--level', '2',               # Level 2: Tests cookies, User-Agent, Referer headers
                '--risk', '2',                # Risk 2: Adds OR-based and heavy time-based tests
                '--timeout', '20',            # Slightly longer timeout for complex payloads
                '--retries', '2',             # Retry failed requests
                '--threads', '3',             # Parallel threads
                '--flush-session',            # Fresh session each test
                '--disable-coloring',         # Clean output
                '--technique', 'BEUST',       # All techniques: Boolean, Error, Union, Stacked, Time
                '--tamper', 'space2comment',  # Basic WAF bypass
                '--random-agent',             # Rotate User-Agent to avoid detection
            ])
            
            # Add --forms if URL doesn't have parameters
            if not has_params:
                cmd.append('--forms')

            logger.debug(f"Running SQLMap: {' '.join(cmd)}")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.SQLMAP_TIMEOUT_PER_ENDPOINT,  # 45 seconds per endpoint
                cwd=tempfile.gettempdir(),
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )

            # Parse and record results
            is_vulnerable = self._parse_sqlmap_results(scan, result, url, test_location)
            return is_vulnerable

        except subprocess.TimeoutExpired:
            logger.warning(f"⏱️ SQLMap timeout for {url} ({self.SQLMAP_TIMEOUT_PER_ENDPOINT}s)")
            return False
        except Exception as e:
            logger.error(f"❌ SQLMap test failed for {url}: {str(e)}")
            return False

    # ============================================================================
    # REPLACED: ENHANCED SQLMAP RESULTS PARSER
    # ============================================================================
    def _parse_sqlmap_results(self, scan, result, target_url, test_location):
        """Parse sqlmap output and create vulnerability records"""
        try:
            output = result.stdout + result.stderr
            
            # Check for SQL injection indicators in output
            is_vulnerable = any(indicator in output.lower() for indicator in 
                             ['is vulnerable', 'injection point', 'sqlmap identified', 'parameter:'])
            
            if is_vulnerable:
                # Extract vulnerability details
                lines = output.split('\n')
                vulnerability_details = []
                payload = "Not specified"
                db_type = "Unknown"
                injection_type = "Unknown"
                parameter_name = "Unknown"
                
                for i, line in enumerate(lines):
                    line_lower = line.lower().strip()
                    
                    if 'parameter:' in line_lower:
                        parameter_name = line.split(':', 1)[1].strip() if ':' in line else "Unknown"
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
                elif 'union' in injection_type.lower():
                    severity = 'critical'
                else:
                    severity = 'medium'
                
                Vulnerability.objects.create(
                    scan=scan,
                    name=f"SQL Injection - {parameter_name}",
                    description=f"SQL injection vulnerability found in parameter '{parameter_name}' at {test_location}",
                    level=severity,
                    details=f"URL: {target_url}\nParameter: {parameter_name}\nInjection Type: {injection_type}\nDatabase: {db_type}\nPayload: {payload}\n\nFull Details:\n" + "\n".join(vulnerability_details),
                    recommendation="Use parameterized queries/prepared statements, implement input validation, and sanitize user inputs. Consider using an ORM that handles SQL injection prevention.",
                    category='sqlInjection'
                )
                
                logger.info(f"✅ SQL injection found: {target_url} (Parameter: {parameter_name})")
                return True
                
            else:
                # Check for potential false negatives
                if 'heuristic' in output.lower() and 'appears to be' in output.lower():
                    Vulnerability.objects.create(
                        scan=scan,
                        name=f"Potential SQL Injection Indicator",
                        description=f"Possible SQL injection indicators detected at {test_location}",
                        level='low',
                        details=f"URL: {target_url}\nSQLMap found potential indicators but couldn't confirm vulnerability.",
                        recommendation="Manual verification recommended. Review input validation and consider penetration testing.",
                        category='sqlInjection'
                    )
                    logger.info(f"⚠️ Potential indicator found: {target_url}")
                
                return False
                
        except Exception as e:
            logger.error(f"Error parsing SQLMap results: {str(e)}")
            return False

    # ============================================================================
    # REPLACED: ENHANCED BASIC SQL INJECTION TESTING
    # ============================================================================
    def _test_sql_injection_basic(self, scan):
        """Enhanced basic SQL injection testing with crawling (fallback when sqlmap not available)"""
        try:
            logger.info(f"Starting enhanced basic SQL injection testing for {scan.url}")
            
            # Crawl to find all forms
            endpoints = self._crawl_site(scan.url, max_depth=2, max_urls=30)
            
            sql_payloads = [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' OR '1'='1' /*",
                "admin'--",
                "' OR 1=1--",
                "' UNION SELECT NULL--",
                "1' AND '1'='1",
            ]
            
            error_patterns = [
                r'mysql_fetch_array\(\)',
                r'ORA-[0-9]+',
                r'Microsoft OLE DB Provider',
                r'SQLSTATE\[\w+\]',
                r'PostgreSQL.*ERROR',
                r'Warning.*mysql_.*',
                r'valid MySQL result',
                r'MySqlClient\.',
                r'SQLite.*error',
                r'syntax error.*SQL',
            ]
            
            tested_count = 0
            for endpoint in endpoints:
                if endpoint['type'] != 'form':
                    continue
                    
                if tested_count >= 20:
                    break
                
                tested_count += 1
                form_url = endpoint['url']
                
                try:
                    try:
                        response = requests.get(endpoint['page_url'], timeout=10, verify=True)
                    except requests.exceptions.SSLError:
                        response = requests.get(endpoint['page_url'], timeout=10, verify=False)
                    soup = BeautifulSoup(response.text, 'html.parser')
                    forms = soup.find_all('form')
                    
                    for form in forms:
                        action = form.get('action', '')
                        if urljoin(endpoint['page_url'], action) != form_url:
                            continue
                        
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
                        
                        for payload in sql_payloads[:4]:
                            test_data = form_data.copy()
                            first_field = next(iter(test_data.keys()))
                            test_data[first_field] = payload
                            
                            try:
                                if method == 'post':
                                    test_response = requests.post(form_url, data=test_data, timeout=5, verify=True)
                                else:
                                    test_response = requests.get(form_url, params=test_data, timeout=5, verify=True)
                                
                                for pattern in error_patterns:
                                    if re.search(pattern, test_response.text, re.IGNORECASE):
                                        Vulnerability.objects.create(
                                            scan=scan,
                                            name=f"Potential SQL Injection - {first_field}",
                                            description=f"Basic SQL injection test detected potential vulnerability",
                                            level='medium',
                                            details=f"URL: {form_url}\nForm Field: {first_field}\nMethod: {method}\nPayload: {payload}",
                                            recommendation="Use parameterized queries and input validation. Professional security testing recommended.",
                                            category='sqlInjection'
                                        )
                                        logger.info(f"Basic test found potential vulnerability: {form_url}")
                                        break
                            
                            except requests.RequestException:
                                continue
                
                except Exception as e:
                    logger.warning(f"Error testing form at {form_url}: {str(e)}")
                    continue
                        
        except Exception as e:
            logger.warning(f"Enhanced basic SQL injection testing failed for {scan.url}: {str(e)}")

    # ============================================================================
    # ENHANCED XSS TESTING - COMPREHENSIVE APPROACH
    # ============================================================================
    def _test_xss_vulnerabilities(self, scan):
        """Enhanced XSS vulnerability testing with multiple attack vectors"""
        try:
            logger.info(f"Starting comprehensive XSS testing for {scan.url}")

            # SSL-flexible request handling
            try:
                response = requests.get(scan.url, timeout=10, verify=True)
            except requests.exceptions.SSLError:
                response = requests.get(scan.url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Test multiple attack vectors
            self._test_form_based_xss(scan, soup)
            self._test_url_parameter_xss(scan, response.url)
            self._test_dom_based_xss(scan, soup)
            
        except Exception as e:
            logger.warning(f"XSS testing failed for {scan.url}: {str(e)}")

    def _test_form_based_xss(self, scan, soup):
        """Test XSS in form inputs"""
        forms = soup.find_all('form')
        
        # Extended payload set with various bypass techniques
        xss_payloads = [
            # Basic payloads
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            
            # Attribute-breaking payloads
            "' onclick='alert(1)",
            '" onmouseover="alert(1)',
            "javascript:alert(1)",
            
            # Filter bypass techniques
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<img src=x onerror=alert`1`>",
            "<svg/onload=alert(1)>",
            
            # HTML entity encoding
            "&lt;script&gt;alert(1)&lt;/script&gt;",
            
            # Double encoding
            "%3Cscript%3Ealert(1)%3C/script%3E",
            
            # Mixed case (filter bypass)
            "<ScRiPt>alert(1)</sCrIpT>",
            
            # Event handlers
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<select onfocus=alert(1) autofocus>",
            "<textarea onfocus=alert(1) autofocus>",
            "<iframe onload=alert(1)>",
            
            # Polyglot payloads
            "javascript:/*--></title></style></textarea></script></xmp>*/alert(1)",
            
            # Data URI
            "<object data='data:text/html,<script>alert(1)</script>'>",
            
            # Template literals
            "${alert(1)}",
            "{{alert(1)}}",
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
            
            # Test each field individually
            for field_name in form_data.keys():
                for payload in xss_payloads[:15]:  # Test more payloads for better coverage
                    test_data = form_data.copy()
                    test_data[field_name] = payload

                    try:
                        target_url = urljoin(scan.url, action) if action else scan.url

                        # SSL-flexible request handling
                        request_kwargs = {
                            'timeout': 5,
                            'allow_redirects': True,
                            'headers': {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                        }

                        try:
                            if method == 'post':
                                test_response = requests.post(target_url, data=test_data, verify=True, **request_kwargs)
                            else:
                                test_response = requests.get(target_url, params=test_data, verify=True, **request_kwargs)
                        except requests.exceptions.SSLError:
                            if method == 'post':
                                test_response = requests.post(target_url, data=test_data, verify=False, **request_kwargs)
                            else:
                                test_response = requests.get(target_url, params=test_data, verify=False, **request_kwargs)
                        
                        # Enhanced detection with context awareness
                        context = self._detect_xss_context(test_response.text, payload)
                        
                        if context:
                            Vulnerability.objects.create(
                                scan=scan,
                                name="Cross-Site Scripting (XSS) Vulnerability",
                                description=f"XSS vulnerability detected in {context['location']}",
                                level='high',
                                details=(
                                    f"Field: {field_name}\n"
                                    f"Form Action: {action}\n"
                                    f"Method: {method}\n"
                                    f"Payload: {payload}\n"
                                    f"Context: {context['type']}\n"
                                    f"Reflection: {context['snippet']}"
                                ),
                                recommendation=(
                                    "1. Implement context-aware output encoding\n"
                                    "2. Use Content Security Policy (CSP)\n"
                                    "3. Sanitize user input on server-side\n"
                                    "4. Use HTTPOnly and Secure flags for cookies\n"
                                    "5. Implement input validation"
                                ),
                                category='xss'
                            )
                            logger.info(f"XSS found in form field '{field_name}': {action}")
                            break  # Move to next field after finding vulnerability
                    
                    except requests.RequestException:
                        continue

    def _test_url_parameter_xss(self, scan, url):
        """Test XSS in URL parameters"""
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        
        if not params:
            return
        
        xss_payloads = [
            "<script>alert(1)</script>",
            "javascript:alert(1)",
            "<img src=x onerror=alert(1)>",
            "';alert(1)//",
            '";alert(1)//',
        ]
        
        for param_name in params.keys():
            for payload in xss_payloads[:3]:
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                try:
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                    request_kwargs = {
                        'params': test_params,
                        'timeout': 5,
                        'allow_redirects': True,
                        'headers': {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                    }

                    try:
                        test_response = requests.get(test_url, verify=True, **request_kwargs)
                    except requests.exceptions.SSLError:
                        test_response = requests.get(test_url, verify=False, **request_kwargs)
                    
                    context = self._detect_xss_context(test_response.text, payload)
                    
                    if context:
                        Vulnerability.objects.create(
                            scan=scan,
                            name="Reflected XSS in URL Parameter",
                            description=f"XSS vulnerability in URL parameter '{param_name}'",
                            level='high',
                            details=(
                                f"Parameter: {param_name}\n"
                                f"Payload: {payload}\n"
                                f"Context: {context['type']}\n"
                                f"URL: {test_response.url}"
                            ),
                            recommendation=(
                                "1. Encode all URL parameters before rendering\n"
                                "2. Implement strict input validation\n"
                                "3. Use parameterized queries\n"
                                "4. Apply Content Security Policy"
                            ),
                            category='xss'
                        )
                        logger.info(f"XSS found in URL parameter '{param_name}'")
                        break
                
                except requests.RequestException:
                    continue

    def _test_dom_based_xss(self, scan, soup):
        """Check for potential DOM-based XSS patterns"""
        dangerous_patterns = [
            r'document\.write\s*\(',
            r'\.innerHTML\s*=',
            r'\.outerHTML\s*=',
            r'eval\s*\(',
            r'setTimeout\s*\(',
            r'setInterval\s*\(',
            r'location\.href\s*=',
            r'location\.search',
            r'document\.URL',
            r'document\.referrer',
            r'window\.name',
        ]
        
        scripts = soup.find_all('script')
        
        for script in scripts:
            if script.string:
                for pattern in dangerous_patterns:
                    if re.search(pattern, script.string):
                        # Check if user input sources are used
                        if any(source in script.string for source in 
                               ['location.search', 'location.hash', 'document.URL', 
                                'document.referrer', 'window.name']):
                            Vulnerability.objects.create(
                                scan=scan,
                                name="Potential DOM-Based XSS",
                                description="Dangerous JavaScript pattern with user-controlled input",
                                level='medium',
                                details=(
                                    f"Pattern found: {pattern}\n"
                                    f"This requires manual verification\n"
                                    f"Script snippet: {script.string[:200]}..."
                                ),
                                recommendation=(
                                    "1. Avoid using dangerous functions with user input\n"
                                    "2. Use textContent instead of innerHTML\n"
                                    "3. Sanitize data before DOM manipulation\n"
                                    "4. Implement CSP with strict directives"
                                ),
                                category='xss'
                            )
                            logger.info("Potential DOM-based XSS pattern detected")
                            break

    def _detect_xss_context(self, response_text, payload):
        """
        Detect if payload is reflected and determine the context.
        Returns dict with context info or None if not vulnerable.
        """
        # Remove whitespace and normalize for better matching
        payload_normalized = payload.strip()
        
        # Check for exact reflection
        if payload_normalized in response_text:
            # Find context around the payload
            payload_index = response_text.find(payload_normalized)
            snippet_start = max(0, payload_index - 50)
            snippet_end = min(len(response_text), payload_index + len(payload_normalized) + 50)
            snippet = response_text[snippet_start:snippet_end]
            
            # Determine context type
            context_type = "Unknown"
            
            if re.search(r'<script[^>]*>.*?' + re.escape(payload_normalized), response_text, re.DOTALL):
                context_type = "JavaScript context"
            elif re.search(r'<[^>]+' + re.escape(payload_normalized) + r'[^>]*>', response_text):
                context_type = "HTML attribute context"
            elif '<' + payload_normalized in response_text or payload_normalized + '>' in response_text:
                context_type = "HTML tag context"
            else:
                context_type = "HTML body context"
            
            return {
                'location': 'Response body',
                'type': context_type,
                'snippet': snippet
            }
        
        # Check for HTML-encoded reflection
        encoded_payload = html.escape(payload_normalized)
        if encoded_payload in response_text and encoded_payload != payload_normalized:
            return None  # Properly encoded, not vulnerable
        
        # Check for URL-encoded reflection
        url_encoded_payload = urllib.parse.quote(payload_normalized)
        if url_encoded_payload in response_text:
            # This might still be vulnerable depending on context
            payload_index = response_text.find(url_encoded_payload)
            snippet_start = max(0, payload_index - 50)
            snippet_end = min(len(response_text), payload_index + len(url_encoded_payload) + 50)
            snippet = response_text[snippet_start:snippet_end]
            
            return {
                'location': 'Response body (URL encoded)',
                'type': 'Potentially vulnerable if decoded client-side',
                'snippet': snippet
            }
        
        return None

    # ============================================================================
    # PORT SCANNING - ENHANCED WITH RISK CLASSIFICATION
    # ============================================================================

    # Port risk classification for accurate vulnerability reporting
    PORT_RISK_LEVELS = {
        # Critical - Direct database/admin access
        'critical': {
            1433: ('MSSQL', 'Microsoft SQL Server exposed - high risk of data breach'),
            1521: ('Oracle', 'Oracle database exposed - high risk of data breach'),
            3306: ('MySQL', 'MySQL database exposed - high risk of data breach'),
            5432: ('PostgreSQL', 'PostgreSQL database exposed - high risk of data breach'),
            27017: ('MongoDB', 'MongoDB exposed - often misconfigured without auth'),
            6379: ('Redis', 'Redis exposed - often has no authentication'),
            9200: ('Elasticsearch', 'Elasticsearch exposed - data leak risk'),
        },
        # High - Remote access and management
        'high': {
            22: ('SSH', 'SSH exposed - ensure key-based auth and fail2ban'),
            23: ('Telnet', 'Telnet sends credentials in plaintext - critical risk'),
            3389: ('RDP', 'Remote Desktop exposed - brute force target'),
            5900: ('VNC', 'VNC exposed - often weak authentication'),
            445: ('SMB', 'SMB exposed - ransomware attack vector'),
            135: ('RPC', 'Windows RPC exposed - exploitation risk'),
            139: ('NetBIOS', 'NetBIOS exposed - information disclosure'),
        },
        # Medium - Mail and file services
        'medium': {
            21: ('FTP', 'FTP exposed - credentials sent in plaintext'),
            25: ('SMTP', 'SMTP exposed - potential spam relay'),
            110: ('POP3', 'POP3 exposed - unencrypted email access'),
            143: ('IMAP', 'IMAP exposed - unencrypted email access'),
            111: ('RPC', 'RPC portmapper exposed'),
        },
        # Low - Standard web services
        'low': {
            80: ('HTTP', 'Web server - ensure HTTPS redirect'),
            443: ('HTTPS', 'Secure web server'),
            993: ('IMAPS', 'Secure IMAP'),
            995: ('POP3S', 'Secure POP3'),
            8080: ('HTTP-Alt', 'Alternative HTTP - often admin panels'),
            8443: ('HTTPS-Alt', 'Alternative HTTPS'),
        }
    }

    def _scan_ports(self, scan):
        """Enhanced port scanning with risk-based classification"""
        try:
            logger.info(f"Starting comprehensive nmap scan for {scan.url}")
            nm = nmap.PortScanner()

            parsed_url = urlparse(scan.url)
            hostname = parsed_url.netloc

            # Remove port from hostname if present
            if ':' in hostname:
                hostname = hostname.split(':')[0]

            # Use the comprehensive port list and add service detection (-sV)
            nm.scan(
                hostname,
                self.SCAN_PORTS,
                arguments='-sT -sV -T4 --host-timeout 45s'
            )

            open_ports_found = []

            for host in nm.all_hosts():
                for protocol in nm[host].all_protocols():
                    ports = nm[host][protocol].keys()
                    for port in ports:
                        port_info = nm[host][protocol][port]
                        state = port_info['state']

                        if state == 'open':
                            service_name = port_info.get('name', 'unknown')
                            service_version = port_info.get('version', '')
                            product = port_info.get('product', '')

                            # Determine risk level and get description
                            level, service_desc, risk_detail = self._classify_port_risk(port, service_name)

                            open_ports_found.append(port)
                            logger.info(f"Found open port {port} ({service_name}) on {host} - Risk: {level}")

                            # Build detailed information
                            details = f"Port: {port}/{protocol.upper()}\n"
                            details += f"State: {state}\n"
                            details += f"Service: {service_name}\n"
                            if product:
                                details += f"Product: {product}\n"
                            if service_version:
                                details += f"Version: {service_version}\n"
                            details += f"\nRisk Assessment: {risk_detail}"

                            # Create vulnerability with context-aware recommendations
                            Vulnerability.objects.create(
                                scan=scan,
                                name=f"Open Port {port} ({service_desc})",
                                description=f"Port {port} is open and running {service_name}",
                                level=level,
                                details=details,
                                recommendation=self._get_port_recommendation(port, service_name),
                                category='openPorts'
                            )

            # Create summary if ports found
            if open_ports_found:
                critical_count = sum(1 for p in open_ports_found if p in self.PORT_RISK_LEVELS.get('critical', {}))
                high_count = sum(1 for p in open_ports_found if p in self.PORT_RISK_LEVELS.get('high', {}))

                summary_level = 'critical' if critical_count > 0 else ('high' if high_count > 0 else 'info')

                Vulnerability.objects.create(
                    scan=scan,
                    name="Port Scan Summary",
                    description=f"Discovered {len(open_ports_found)} open ports",
                    level='none',
                    details=f"Open ports: {', '.join(map(str, sorted(open_ports_found)))}\n\nCritical risk ports: {critical_count}\nHigh risk ports: {high_count}",
                    recommendation="Review all open ports and close unnecessary services. Use firewall rules to restrict access.",
                    category='openPorts'
                )

        except Exception as e:
            logger.warning(f"Port scan failed for {scan.url}: {str(e)}")
            Vulnerability.objects.create(
                scan=scan,
                name="Port Scan Incomplete",
                description="Could not complete port scanning",
                level='none',
                details=f"Error: {str(e)}\n\nThis may be due to firewall restrictions or network issues.",
                recommendation="Try scanning from a different network or check if nmap is properly installed.",
                category='openPorts'
            )

    def _classify_port_risk(self, port, service_name):
        """Classify port risk based on port number and service"""
        for level, ports in self.PORT_RISK_LEVELS.items():
            if port in ports:
                service_desc, risk_detail = ports[port]
                return level, service_desc, risk_detail

        # Default classification for unknown ports
        if port < 1024:
            return 'medium', service_name.upper() or 'Unknown', 'Well-known port - verify service necessity'
        else:
            return 'low', service_name.upper() or 'Unknown', 'High port - likely application service'

    def _get_port_recommendation(self, port, service_name):
        """Get specific security recommendation for a port"""
        recommendations = {
            21: "Disable FTP and use SFTP instead. If FTP is required, use FTPS with strong encryption.",
            22: "Use key-based authentication, disable root login, implement fail2ban, and use non-standard port.",
            23: "URGENT: Disable Telnet immediately. Use SSH for remote access instead.",
            25: "Configure SMTP authentication, implement SPF/DKIM/DMARC, and restrict relay access.",
            80: "Redirect all HTTP traffic to HTTPS. Implement HSTS header.",
            110: "Use POP3S (port 995) instead for encrypted email access.",
            135: "Block from external access. Only allow on internal networks if required.",
            139: "Block from external access. Disable if NetBIOS is not required.",
            143: "Use IMAPS (port 993) instead for encrypted email access.",
            443: "Ensure TLS 1.2+ is used. Disable weak ciphers. Implement certificate monitoring.",
            445: "Block from external access. Critical ransomware vector (WannaCry, NotPetya).",
            1433: "CRITICAL: Never expose to internet. Use VPN or IP whitelist for remote access.",
            1521: "CRITICAL: Never expose to internet. Use Oracle Net encryption and strong authentication.",
            3306: "CRITICAL: Never expose to internet. Use SSL connections and IP restrictions.",
            3389: "Use Network Level Authentication, strong passwords, and consider RDP Gateway.",
            5432: "CRITICAL: Never expose to internet. Use SSL and pg_hba.conf restrictions.",
            5900: "Use VNC over SSH tunnel. Never expose directly to internet.",
            6379: "CRITICAL: Enable Redis AUTH, bind to localhost, use firewall rules.",
            8080: "Often admin panels - ensure authentication and restrict access.",
            27017: "CRITICAL: Enable MongoDB authentication. Never expose without auth.",
        }

        return recommendations.get(port, f"Verify if port {port} ({service_name}) is necessary. Implement access controls and monitoring.")

    # ============================================================================
    # WEBSITE ANALYSIS
    # ============================================================================
    def _analyze_website(self, scan):
        """Analyze website for security issues"""
        try:
            logger.info(f"Starting website analysis for {scan.url}")
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            # Try with SSL verification first, fall back to unverified if it fails
            try:
                response = requests.get(scan.url, headers=headers, timeout=15, verify=True)
            except requests.exceptions.SSLError:
                logger.warning(f"SSL verification failed for {scan.url}, retrying without verification")
                response = requests.get(scan.url, headers=headers, timeout=15, verify=False)
                # Report SSL issue as a vulnerability
                Vulnerability.objects.create(
                    scan=scan,
                    name="SSL/TLS Certificate Issue",
                    description="The site's SSL certificate could not be verified",
                    level='medium',
                    details="The SSL certificate is either self-signed, expired, or has an invalid chain.",
                    recommendation="Install a valid SSL certificate from a trusted Certificate Authority (CA). Consider using Let's Encrypt for free certificates.",
                    category='other'
                )
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