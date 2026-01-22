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
- الاختبار الأمني المصرح به
- بحوث Bug Bounty
- البيئات التعليمية

**لا تستخدم** هذه الأداة على أنظمة لا تملك إذن صريح لاختبارها.

## 📖 التوثيق

- [دليل البدء السريع](QUICK_START.md)
- [دليل الاختبار](TESTING_GUIDE.md)
- [حالات الاختبار](TEST_CASES.ts)
- [حالة المشروع](PROJECT_STATUS.md)

## 🏗️ البنية

```
├── client/          # React frontend
│   └── src/        
│       ├── pages/   # صفحات التطبيق
│       └── components/  # مكونات UI
├── server/          # Express backend
│   ├── scanner/     # محرك الفحص
│   └── routes.ts    # API endpoints
├── scanner_cli/     # Python CLI scanner
│   ├── scanner.py   # محرك الفحص الرئيسي
│   ├── detector.py  # كاشف SQL injection
│   └── reporter.py  # مولد التقارير
├── shared/          # أنواع مشتركة
└── migrations/      # Database migrations
```

## 🤝 المساهمة

المساهمات مرحب بها! الرجاء:
1. Fork المشروع
2. إنشاء branch للميزة (`git checkout -b feature/AmazingFeature`)
3. Commit التغييرات (`git commit -m 'Add AmazingFeature'`)
4. Push إلى Branch (`git push origin feature/AmazingFeature`)
5. فتح Pull Request

## 📄 الترخيص

هذا المشروع مرخص تحت MIT License.

## 🔗 روابط مفيدة

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [PortSwigger SQL Injection](https://portswigger.net/web-security/sql-injection)

## 📧 الدعم

للمساعدة أو الإبلاغ عن المشاكل، يرجى فتح issue في GitHub.

---

صُنع بـ ❤️ للمجتمع الأمني
