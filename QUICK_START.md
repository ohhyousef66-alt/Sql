# Quick Start Guide - SQL Injection Scanner

## 🚀 Fastest Way to Test

### Option 1: Docker Compose (Recommended - 2 minutes)

```bash
# Start PostgreSQL + Scanner
docker-compose up --build

# The scanner will start on http://localhost:3000
```

Then test with:
```bash
curl -X POST http://localhost:3000/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "targetUrl": "http://testphp.vulnweb.com/artists.php",
    "scanMode": "sqli",
    "threads": 10
  }'
```

### Option 2: Local Development (Manual)

```bash
# 1. Install dependencies
npm install

# 2. Set up database
export DATABASE_URL=postgresql://user:password@localhost:5432/sqli_scanner

# 3. Create database schema
npm run db:push

# 4. Start dev server
npm run dev

# 5. In another terminal, create a scan
curl -X POST http://localhost:3000/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "targetUrl": "http://testphp.vulnweb.com/artists.php",
    "scanMode": "sqli",
    "threads": 10
  }'
```

## 📊 Monitor the Scan

### Get Scan Status
```bash
curl http://localhost:3000/api/scans/1
```

### Watch Live Logs
```bash
curl http://localhost:3000/api/scans/1/logs
```

### Get Vulnerabilities Found
```bash
curl http://localhost:3000/api/scans/1/vulnerabilities
```

### View Traffic Log
```bash
curl http://localhost:3000/api/scans/1/traffic
```

## 🎯 Testing Targets

### Primary Test Target
- **URL**: http://testphp.vulnweb.com/
- **Vulnerable Parameters**: `artist`, `cat`, `id`
- **Expected**: Multiple SQL injection methods detected

### Example Vulnerable Endpoints
```
http://testphp.vulnweb.com/artists.php?artist=1
http://testphp.vulnweb.com/categories.php?cat=1
http://testphp.vulnweb.com/product.php?id=1
```

## 📈 Expected Results

When scanning testphp.vulnweb.com, you should see:
- ✅ Boolean-based SQL injection (artist parameter)
- ✅ Error-based SQL injection (id parameter)
- ✅ Time-based blind SQL injection (cat parameter)
- ✅ Database type detection (MySQL)
- ✅ Confidence scores 85-95%

## 🔧 Configuration Options

### Increase Concurrency (Faster but More Load)
```bash
curl -X POST http://localhost:3000/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "targetUrl": "http://testphp.vulnweb.com/artists.php",
    "scanMode": "sqli",
    "threads": 50
  }'
```

### Conservative Scanning (Slower but Quieter)
```bash
curl -X POST http://localhost:3000/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "targetUrl": "http://testphp.vulnweb.com/artists.php",
    "scanMode": "sqli",
    "threads": 5
  }'
```

## 📱 Web Dashboard

Once the server is running, visit:
```
http://localhost:3000
```

- View all scans
- Monitor scan progress
- See live attack telemetry
- View vulnerability details
- Export PDF reports

## 🐛 Troubleshooting

### Port 3000 Already in Use
```bash
# Use different port
PORT=3001 npm run dev
```

### Database Connection Error
```bash
# Check PostgreSQL is running
psql -c "SELECT 1" postgresql://user:password@localhost:5432/sqli_scanner

# Or use Docker
docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=password postgres:15
```

### Scan Freezing
- The scanner has built-in timeout protection (60s per URL)
- If stuck, cancel via: `curl -X POST http://localhost:3000/api/scans/1/cancel`

## 📚 Documentation

- **TESTING_GUIDE.md** - Detailed testing procedures
- **TEST_CASES.ts** - Example payloads and test cases
- **PROJECT_COMPLETION_SUMMARY.md** - Project overview
- **IMPROVEMENTS_LOG.md** - All improvements made

## ✨ Key Features

✅ Boolean-based SQL injection detection
✅ Error-based SQL injection detection
✅ Time-based blind SQL injection detection
✅ Union-based SQL injection detection
✅ Second-order SQL injection detection
✅ WAF bypass strategies
✅ Rate limiting handling
✅ Multi-threaded async scanning
✅ Real-time progress dashboard
✅ Traffic logging
✅ PDF report generation

---

**Ready to test?** Run `docker-compose up` now!
