# SecScan.io - SQL Injection Detection Engine

## Overview
SecScan.io is a specialized SQL injection detection engine designed for professional-grade vulnerability scanning, prioritizing zero false positives. It exclusively focuses on various types of SQL injection: Error-based, Boolean-based, Time-based, Union-based, and Stacked Query Injection across multiple database systems. The project aims to deliver a highly accurate and reliable tool for security professionals, explicitly disabling all other vulnerability types.

## User Preferences
Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend
- **Framework**: React 18 with TypeScript
- **Styling**: Tailwind CSS with shadcn/ui (New York style)
- **UI/UX Decisions**: Dark-themed cybersecurity aesthetic, animated dashboard elements, real-time attack telemetry (War Room Dashboard) with metrics like RPS, payload queue, and WAF/CAPTCHA blocks.

### Backend
- **Runtime**: Node.js with Express and TypeScript
- **API Design**: RESTful endpoints with Zod validation
- **Database ORM**: Drizzle ORM with PostgreSQL
- **Asynchronous Scanning**: Focused scanner architecture for asynchronous SQL injection scans.

### Data Layer
- **Database**: PostgreSQL
- **Core Tables**: `scans`, `vulnerabilities`, `scanLogs`, `trafficLogs`.

### Core Features & Design Principles
- **SQL-Only Focus**: Exclusively detects SQL Injection; other vulnerability types are disabled.
- **Zero False Positives**: Prioritizes accuracy over detection breadth; "It is acceptable to miss vulnerabilities. It is NOT acceptable to report false positives."
- **Zero-Speed Directive**: Scans complete only when the work queue is empty, with all early rejection logic and budget enforcements disabled.
- **Configurable Scanning**: User-adjustable thread count (1-50), with a default of 10.
- **Confidence Scoring**: Vulnerabilities are categorized as "CONFIRMED" (90-100%) or "POTENTIAL" (50-89%).
- **Enhanced Crawler**: Deep discovery including JavaScript parsing, form extraction, and OpenAPI/Swagger detection.
- **Comprehensive SQLi Module**: Detects error-based, union-based, boolean-blind, and time-based SQLi with multi-request baselining.
- **Context-Aware Payloads**: Automatic detection of parameter context (numeric, string, double-quote, parentheses) for tailored payload generation and filtering.
- **WAF Bypass**: Automatic payload mutation with various encoding and tamping strategies (15 total). Header rotation on blocks.
- **Global Payload Repository**: Over 309 diverse payloads across 7 categories.
- **Multi-Target Scanning**: Production-ready parent/child scan architecture for batch scanning.
- **High-Fidelity Traffic Logging**: Complete request/response capture for payload analysis.
- **Adaptive Detection Engine**: Uses high-signal boolean probes for diagnostics without skipping full testing.
- **DOM-Aware Normalization**: Strips volatile content for accurate differential analysis in boolean-based detection (using SHA-256 structural hashing).
- **Progressive Time-Based Detection**: Utilizes delays of [2, 5, 8] seconds with 5-sample baseline and 3σ statistical timing threshold.
- **High-Performance Async Model**: Employs `ConnectionPoolManager` (200 max sockets) and `TieredConcurrencyManager` (100 high/10 low concurrent requests).
- **Parallel Crawler**: Queue-based parallel URL processing with configurable concurrency.
- **Second-Order SQLi Detection**: Store-trigger pattern detection across different URL pairs.
- **UNRESTRICTED OFFENSIVE MODE**: No mandatory pauses on 403/429/CAPTCHA; logs and continues immediately, prioritizing maximum throughput.
- **Out-of-Band (OOB) SQLi Detection**: DNS exfiltration payloads for various databases (MySQL, PostgreSQL, Oracle, MSSQL).
- **HTTP Header & Hidden Field Fuzzing**: Discovers and tests loggable headers and hidden input fields.
- **Dynamic WAF Tamping Rotation**: WAF-specific tamping profiles for 10+ vendors with 11 strategies and automatic combination.
- **Statistical Confidence Engine**: 5-sample baseline with 3σ threshold for timing analysis and variance ratio validation.
- **Live Payload View Dashboard**: Real-time display of current payload, type, confidence, database, and context.
- **Adaptive Testing Pipeline**: Includes self-scaling concurrency, heuristic probing, intelligent payload prioritization, resource-efficient discovery, and dynamic progress tracking.
- **Mass-Scan Management Layer**: Enterprise-scale scanning for up to 5,000 concurrent targets with a 5-stage pipeline (Discovery, Heuristic Probing, Boolean/Error Context, Deep Fuzzing, Confirmation). Supports file-based target management (.txt/.csv) and tracking of staged targets.
  - **State Machine**: Files transition through pending → processing → completed with high-water mark protection
  - **Auto-Advancement**: Targets automatically progress through stages after successful completion
  - **Stop/Cancel Safety**: Guarded state transitions prevent regression of completed runs
  - **Real-time Progress**: 2-second auto-refresh for stage runs with live target counts

## Deployment Configuration

### Railway Deployment
- **Config Files**: `railway.json` and `nixpacks.toml` configure Railway deployment
- **Playwright Browsers**: Automatically installed during build phase via nixpacks
- **Node.js Memory Limits**: High-performance mode with 8GB heap (`--max-old-space-size=8192`) and 128MB semi-space (`--max-semi-space-size=128`) for handling 5,000 concurrent threads
- **System Dependencies**: Chromium and all required libraries bundled via Nix packages
- **Health Check**: Configured at `/api/health` with 300s timeout

## External Dependencies

### Database
- **PostgreSQL**: Primary data store.

### HTTP/Networking
- **Axios**: HTTP client.
- **Cheerio**: HTML parsing.

### PDF Generation
- **PDFKit**: Server-side PDF document generation.

### UI Components
- **Radix UI**: Headless component primitives.
- **shadcn/ui**: Pre-styled component library.
- **Lucide React**: Icon library.