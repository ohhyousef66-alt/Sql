# SQL Injection Scanner - Enterprise Grade

Professional web vulnerability scanner with **484 payloads** matching SQLi Dumper's capabilities, plus enterprise features like web UI, real-time monitoring, and automated reporting.

## Tech Stack

- **Backend:** Express.js + TypeScript
- **Frontend:** React 18 + TypeScript + Shadcn/UI  
- **Database:** PostgreSQL + Drizzle ORM
- **Scanner:** Multi-threaded detection engine with 484 payloads

## Core Features - SQLi Dumper Level

### Detection Capabilities (484 Payloads)
- **Error-based SQLi:** 98 payloads with EXTRACTVALUE/UPDATEXML
- **Boolean-based blind SQLi:** 55 payloads with binary search
- **Time-based blind SQLi:** 50 payloads with SLEEP/WAITFOR
- **UNION-based SQLi:** 88 payloads for direct extraction
- **Stacked queries:** 31 payloads for command injection
- **Second-order SQLi:** Advanced delayed injection
- **WAF bypass:** 60 techniques (/*!*/, encoding, case variation)
- **Out-of-band:** 15 DNS exfiltration payloads
- **Advanced exploitation:** 22 file read/write payloads
- **DBMS-specific:** 65 payloads (MySQL, PostgreSQL, MSSQL, Oracle)

### Data Dumping (Matches SQLi Dumper)
- Database enumeration (list all databases)
- Table enumeration (list tables in database)
- Column enumeration (extract column names/types)
- Data extraction (dump table contents)
- Multiple extraction techniques (error, UNION, blind)
- File operations (LOAD_FILE, INTO OUTFILE)
- Command execution (xp_cmdshell, pg_read_file)

### Enterprise Features (Better than SQLi Dumper)
- **Web UI:** Beautiful React dashboard (SQLi Dumper is CLI-only)
- **Real-time monitoring:** Live scan progress with metrics
- **Report generation:** Professional PDF + JSON + TXT reports
- **Results persistence:** PostgreSQL storage (SQLi Dumper saves to files)
- **API access:** RESTful API for automation
- **Multi-user:** Authentication and scan history
- **Dark mode:** Cybersecurity theme

## Installation

```bash
# Install dependencies
npm install

# Configure environment
cp .env.example .env
# Edit .env with your DATABASE_URL

# Setup database
npm run db:push

# Start server
npm run dev
```

Server runs on http://localhost:5000

## Project Structure

```
server/
  ├── scanner/           # Detection engine
  │   ├── modules/       # SQLi, XSS, etc.
  │   ├── pipeline/      # Staged scanning pipeline
  │   └── utils/         # Helper functions
  ├── routes.ts          # API endpoints
  └── storage.ts         # Database layer
client/
  ├── src/
  │   ├── pages/         # React pages
  │   └── components/    # UI components
shared/
  └── schema.ts          # Shared types
scanner_cli/             # Python CLI tool
```

## Available Commands

```bash
npm run dev        # Development server
npm run build      # Production build
npm run start      # Production server
npm run check      # TypeScript validation
npm run db:push    # Database migrations
```

## Security Warning

⚠️ **Authorized Testing Only**

This tool is designed for security professionals and penetration testers. Only use against systems you have explicit written permission to test. Unauthorized scanning is illegal.

## License

MIT

## Useful Links

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [PortSwigger SQL Injection](https://portswigger.net/web-security/sql-injection)

---

Made with ❤️ for the security community
