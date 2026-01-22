# SQL Injection Scanner

Professional web vulnerability scanner focused on SQL injection detection with real-time monitoring and automated data extraction capabilities.

## Tech Stack

- **Backend:** Express.js + TypeScript
- **Frontend:** React 18 + TypeScript + Shadcn/UI  
- **Database:** PostgreSQL + Drizzle ORM
- **Scanner:** Multi-threaded detection engine with adaptive testing

## Core Features

### Detection Capabilities
- Error-based SQL injection
- Boolean-based blind SQLi
- Time-based blind SQLi
- UNION-based SQLi
- Second-order SQLi
- WAF bypass strategies

### UI & Reporting
- Real-time scan progress tracking
- Live traffic log inspection
- Vulnerability severity classification
- PDF report generation
- Dark mode cybersecurity theme

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
