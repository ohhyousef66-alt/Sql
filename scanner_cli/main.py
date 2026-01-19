#!/usr/bin/env python3
"""
SecScan.io - SQL Injection Detection Engine
Professional-grade CLI scanner with multi-threaded fuzzing

Usage:
    python main.py --url <target> [options]

Examples:
    python main.py --url "http://example.com/page.php?id=1"
    python main.py --url "http://example.com/page.php?id=1" --threads 20 --depth 3
    python main.py --url "http://example.com/page.php?id=1" --types error_based,boolean_based
    python main.py --url "http://example.com/page.php?id=1" --output results.json --verbose
"""

import argparse
import sys
import os
import warnings
from typing import List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner import SQLiScanner, ScanProgress
from reporter import generate_reports, ReportGenerator
from detector import SQLiDetector

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

VERSION = "1.0.0"

BANNER = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ███████╗ ██████╗ ██╗     ██╗    ███████╗ ██████╗ █████╗ ███╗║
║   ██╔════╝██╔═══██╗██║     ██║    ██╔════╝██╔════╝██╔══██╗████║
║   ███████╗██║   ██║██║     ██║    ███████╗██║     ███████║██╔█║
║   ╚════██║██║▄▄ ██║██║     ██║    ╚════██║██║     ██╔══██║██║╚║
║   ███████║╚██████╔╝███████╗██║    ███████║╚██████╗██║  ██║██║ ║
║   ╚══════╝ ╚══▀▀═╝ ╚══════╝╚═╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝ ║
║                                                               ║
║        SQL Injection Scanner v{version} - Multi-threaded         ║
║                Professional Vulnerability Testing             ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
""".format(version=VERSION)


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        prog="sqliscan",
        description="SQL Injection Scanner - Professional Detection Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --url "http://example.com/page.php?id=1"
  %(prog)s --url "http://example.com/page.php?id=1" --threads 20
  %(prog)s --url "http://example.com/page.php?id=1" --types error_based,union_based
  %(prog)s --url "http://example.com/page.php?id=1" --output report --verbose
  %(prog)s --url "http://example.com/page.php?id=1" --delay 0.5 --timeout 15

Payload Types:
  error_based    - Test for SQL syntax errors in response
  boolean_based  - Test for boolean-based blind injection
  time_based     - Test for time-based blind injection
  union_based    - Test for UNION-based injection
  stacked_queries - Test for stacked query injection
  waf_bypass     - Use WAF bypass techniques
  oob_detection  - Out-of-band detection payloads
        """
    )
    
    parser.add_argument(
        "-u", "--url",
        required=True,
        help="Target URL with parameters (e.g., http://example.com/page.php?id=1)"
    )
    
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=10,
        help="Number of concurrent threads (default: 10)"
    )
    
    parser.add_argument(
        "-d", "--depth",
        type=int,
        default=1,
        help="Crawl depth for discovering additional URLs (default: 1)"
    )
    
    parser.add_argument(
        "--types",
        type=str,
        default=None,
        help="Comma-separated payload types (default: all)"
    )
    
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)"
    )
    
    parser.add_argument(
        "--delay",
        type=float,
        default=0,
        help="Delay between requests in seconds (default: 0)"
    )
    
    parser.add_argument(
        "-o", "--output",
        type=str,
        default="scan_results",
        help="Output filename prefix (default: scan_results)"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Only generate JSON report"
    )
    
    parser.add_argument(
        "--txt-only",
        action="store_true",
        help="Only generate TXT report"
    )
    
    parser.add_argument(
        "--payloads",
        type=str,
        default="payloads.json",
        help="Custom payloads file (default: payloads.json)"
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version=f"SecScan.io v{VERSION}"
    )
    
    return parser.parse_args()


def validate_url(url: str) -> bool:
    """Validate target URL format"""
    if not url.startswith(("http://", "https://")):
        print("[!] Error: URL must start with http:// or https://")
        return False
    return True


def progress_callback(progress: ScanProgress) -> None:
    """Callback for scan progress updates"""
    pass


def main() -> int:
    """Main entry point"""
    print(BANNER)
    
    args = parse_arguments()
    
    if not validate_url(args.url):
        return 1
    
    payload_types: Optional[List[str]] = None
    if args.types:
        payload_types = [t.strip() for t in args.types.split(",")]
        print(f"[*] Using payload types: {payload_types}")
    
    payloads_file = args.payloads
    if not os.path.isabs(payloads_file):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        payloads_file = os.path.join(script_dir, payloads_file)
    
    try:
        scanner = SQLiScanner(
            payloads_file=payloads_file,
            threads=args.threads,
            timeout=args.timeout,
            delay=args.delay,
            verbose=args.verbose,
            progress_callback=progress_callback if args.verbose else None
        )
        
        results = scanner.scan(args.url, payload_types)
        
        json_file = f"{args.output}.json"
        txt_file = f"{args.output}.txt"
        
        reporter = ReportGenerator(results, scanner.progress, args.url)
        
        if args.json_only:
            reporter.generate_json(json_file)
            print(f"\n[+] JSON report saved: {json_file}")
        elif args.txt_only:
            reporter.generate_txt(txt_file)
            print(f"\n[+] TXT report saved: {txt_file}")
        else:
            reporter.generate_json(json_file)
            reporter.generate_txt(txt_file)
            print(f"\n[+] Reports saved:")
            print(f"    - JSON: {json_file}")
            print(f"    - TXT:  {txt_file}")
        
        reporter.print_summary()
        
        return 0
        
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        return 130
    except Exception as e:
        print(f"\n[!] Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
