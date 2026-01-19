# SQL Injection Scanner - Testing Guide

## Quick Test Setup

### Prerequisites
1. PostgreSQL database (local or remote)
2. Node.js 18+ and npm
3. Environment variables configured

### Environment Configuration

Create a `.env.local` file in the root directory:

```bash
# Database
DATABASE_URL=postgresql://user:password@localhost:5432/sqli_scanner

# Server
NODE_ENV=development
PORT=3000
```

Or set environment variables:

```bash
export DATABASE_URL=postgresql://user:password@localhost:5432/sqli_scanner
```

### Local Testing with Docker PostgreSQL

```bash
# Start PostgreSQL in Docker
docker run -d \
  --name postgres-sqli \
  -e POSTGRES_PASSWORD=password \
  -e POSTGRES_DB=sqli_scanner \
  -p 5432:5432 \
  postgres:15

# Wait for database to be ready
sleep 5

# Set environment variable
export DATABASE_URL=postgresql://postgres:password@localhost:5432/sqli_scanner

# Run migrations
npm run db:push

# Start development server
npm run dev
```

## Testing Against testphp.vulnweb.com

The scanner is specifically optimized for SQL injection detection on vulnerable targets.

### Target URL
- **Main Site**: `http://testphp.vulnweb.com/`
- **Vulnerable Parameters**: `cat`, `artist`, `id`, `search`
- **Known SQLi Endpoints**:
  - `http://testphp.vulnweb.com/artists.php?artist=1`
  - `http://testphp.vulnweb.com/product.php?id=1`
  - `http://testphp.vulnweb.com/categories.php?cat=1`

### Via REST API

```bash
# Create a new scan
curl -X POST http://localhost:3000/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "targetUrl": "http://testphp.vulnweb.com/artists.php",
    "scanMode": "sqli",
    "threads": 10
  }'

# Response:
# {
#   "id": 1,
#   "targetUrl": "http://testphp.vulnweb.com/artists.php",
#   "status": "scanning",
#   "progress": 5,
#   "scanMode": "sqli"
# }

# Get scan details
curl http://localhost:3000/api/scans/1

# Get vulnerabilities found
curl http://localhost:3000/api/scans/1/vulnerabilities

# Get live logs
curl http://localhost:3000/api/scans/1/logs

# Get traffic logs
curl http://localhost:3000/api/scans/1/traffic
```

### Via CLI (Python)

```bash
# Run scanner CLI
cd scanner_cli
python main.py --url "http://testphp.vulnweb.com/artists.php?artist=1" --threads 10

# With output file
python main.py --url "http://testphp.vulnweb.com/artists.php?artist=1" \
  --output results.json \
  --verbose
```

## Expected Detection Results

### Boolean-Based SQLi Detection
When testing `http://testphp.vulnweb.com/artists.php?artist=1`:

**Payload**: `artist=1 AND 1=1`
- **Baseline Response**: Normal page (e.g., shows artists)
- **True Condition**: Same as baseline (vulnerability indicator)
- **False Condition**: Different from baseline (confirms SQLi)
- **Result**: CONFIRMED SQL Injection

### Time-Based Blind SQLi
**Payload**: `artist=1 AND SLEEP(5)`
- **Normal Response Time**: ~200-300ms
- **With SLEEP(5)**: ~5200-5300ms
- **Statistical Analysis**: 5 second delay detected
- **Result**: CONFIRMED SQL Injection

### Error-Based SQLi
**Payload**: `artist=1'`
- **Expected Error**: SQL syntax error in response
- **Pattern Matching**: Identifies database error messages
- **Database Detection**: MySQL, PostgreSQL, Oracle, MSSQL
- **Result**: CONFIRMED SQL Injection

## Scan Phases

The scanner executes in phases:

1. **Initialization** (5%) - Setup and configuration
2. **Crawling** (10%) - Discover URLs and parameters
3. **Parameter Discovery** (15%) - Identify SQL-sensitive parameters
4. **Baseline Profiling** (25%) - Establish baseline responses
5. **Error-Based SQLi** (40%) - Test for error-based injection
6. **Boolean-Based SQLi** (60%) - Test for blind boolean injection
7. **Time-Based SQLi** (80%) - Test for time-based blind injection
8. **Second-Order SQLi** (90%) - Test for stored/second-order injection
9. **Final Verification** (95-100%) - Verify and report findings

## Expected Findings for testphp.vulnweb.com

### Confirmed Vulnerabilities
- **artist parameter**: Multiple SQL injection methods
- **cat parameter**: Category SQL injection
- **id parameter**: Product ID SQL injection

### Vulnerability Details
```json
{
  "type": "sqli",
  "severity": "critical",
  "verificationStatus": "confirmed",
  "confidence": 95,
  "parameter": "artist",
  "url": "http://testphp.vulnweb.com/artists.php",
  "payload": "1' AND '1'='1",
  "evidence": "Response differs between true and false conditions",
  "description": "Boolean-based blind SQL injection detected"
}
```

## War Room Dashboard

When scanning, check the live dashboard at:
```
http://localhost:3000/scans/<scan-id>
```

**Live Metrics**:
- RPS (Requests Per Second)
- Payload Queue Progress
- Current Phase
- WAF/CAPTCHA Blocks Encountered
- Current Payload Being Tested
- Confidence Score
- Detected Database Type

## Troubleshooting

### "DATABASE_URL must be set"
```bash
# Set the environment variable
export DATABASE_URL=postgresql://user:password@localhost:5432/sqli_scanner

# Or in .env.local
DATABASE_URL=postgresql://user:password@localhost:5432/sqli_scanner
```

### Connection Refused
```bash
# Check if PostgreSQL is running
psql -U postgres -d sqli_scanner -c "SELECT 1"

# Start PostgreSQL service
sudo systemctl start postgresql
# or
brew services start postgresql
```

### Scan Freezing
The scanner has been optimized to prevent freezing:
- Request timeout: 60 seconds per URL
- Phase timeout: Configurable (default: unlimited)
- Watchdog timer: Monitors for stuck operations
- Stall detection: 1 hour of no activity triggers termination

If a scan appears stuck:
```bash
# Cancel the scan
curl -X POST http://localhost:3000/api/scans/<scan-id>/cancel
```

### False Negatives
If SQL injection is not detected on a known vulnerable parameter:

1. **Verify Target Accessibility**:
```bash
curl -I http://testphp.vulnweb.com/artists.php
```

2. **Check Logs**:
- Review live logs for WAF blocks
- Check defense awareness logs for rate limiting

3. **Enable Verbose Logging**:
```bash
# In development
npm run dev
# Logs printed to console
```

4. **Manual Test**:
```bash
# Test with curl
curl "http://testphp.vulnweb.com/artists.php?artist=1%20AND%201=1"
curl "http://testphp.vulnweb.com/artists.php?artist=1%20AND%201=2"

# Compare responses
```

## Performance Benchmarks

### Typical Scan Times
- **Single Parameter**: 30-120 seconds (5+ payloads with verification)
- **5 Parameters**: 2-5 minutes
- **10+ URLs**: 5-15 minutes
- **Multiple detection types**: +30-60% time

### Concurrency Settings
```bash
# Conservative (less resources, slower)
threads: 2-5

# Balanced (recommended)
threads: 10

# Aggressive (more resources, faster)
threads: 20-50

# Maximum (all resources)
threads: 100
```

## Success Criteria

A successful scan against testphp.vulnweb.com should:

✅ Detect at least 3 confirmed SQL injection vulnerabilities
✅ Identify parameter types correctly (numeric, string, etc.)
✅ Detect database type (MySQL, PostgreSQL, Oracle, etc.)
✅ Provide evidence for each finding
✅ Complete without freezing
✅ Report both confirmed and potential findings
✅ Show detailed traffic logs
✅ Include attack chains if applicable

---

**For more information**: See PROJECT_COMPLETION_SUMMARY.md and IMPROVEMENTS_LOG.md
