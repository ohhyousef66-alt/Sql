"""
Report Generation Module
Export scan findings to JSON and TXT formats
"""

import json
from datetime import datetime
from typing import List, Dict, Any
from dataclasses import asdict

from scanner import ScanResult, ScanProgress


class ReportGenerator:
    """Generate scan reports in multiple formats"""
    
    def __init__(self, results: List[ScanResult], progress: ScanProgress, target_url: str):
        self.results = results
        self.progress = progress
        self.target_url = target_url
        self.timestamp = datetime.now()
    
    def generate_json(self, output_file: str = "scan_results.json") -> str:
        """Generate JSON format report"""
        report = {
            "scan_metadata": {
                "tool": "SQL Injection Scanner",
                "version": "1.0.0",
                "timestamp": self.timestamp.isoformat(),
                "target_url": self.target_url,
            },
            "scan_statistics": {
                "total_payloads_tested": self.progress.tested_payloads,
                "total_vulnerabilities": len(self.results),
                "unique_vulnerable_params": len(self._get_unique_params()),
                "elapsed_time_seconds": round(self.progress.elapsed_time, 2),
                "requests_per_second": round(self.progress.requests_per_second, 2),
            },
            "summary": self._generate_summary(),
            "vulnerabilities": [self._format_result(r) for r in self.results],
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return output_file
    
    def generate_txt(self, output_file: str = "scan_results.txt") -> str:
        """Generate plain text report"""
        lines = []
        lines.append("=" * 70)
        lines.append("SQL Injection Scan Report")
        lines.append("=" * 70)
        lines.append("")
        lines.append(f"Target URL: {self.target_url}")
        lines.append(f"Scan Date: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")
        lines.append("-" * 70)
        lines.append("SCAN STATISTICS")
        lines.append("-" * 70)
        lines.append(f"Total Payloads Tested: {self.progress.tested_payloads}")
        lines.append(f"Total Vulnerabilities: {len(self.results)}")
        lines.append(f"Unique Vulnerable Params: {len(self._get_unique_params())}")
        lines.append(f"Scan Duration: {self.progress.elapsed_time:.2f} seconds")
        lines.append(f"Request Rate: {self.progress.requests_per_second:.2f} req/sec")
        lines.append("")
        
        if self.results:
            lines.append("-" * 70)
            lines.append("VULNERABILITY SUMMARY")
            lines.append("-" * 70)
            summary = self._generate_summary()
            
            lines.append(f"\nBy Severity:")
            lines.append(f"  Critical (90-100% confidence): {summary['by_severity']['critical']}")
            lines.append(f"  High (70-89% confidence):      {summary['by_severity']['high']}")
            lines.append(f"  Medium (50-69% confidence):    {summary['by_severity']['medium']}")
            lines.append(f"  Low (<50% confidence):         {summary['by_severity']['low']}")
            
            lines.append(f"\nBy Database Type:")
            for db, count in summary['by_database'].items():
                lines.append(f"  {db}: {count}")
            
            lines.append(f"\nBy Injection Type:")
            for itype, count in summary['by_injection_type'].items():
                lines.append(f"  {itype}: {count}")
            
            lines.append("")
            lines.append("-" * 70)
            lines.append("DETAILED FINDINGS")
            lines.append("-" * 70)
            
            for i, result in enumerate(self.results, 1):
                lines.append(f"\n[{i}] {self._get_severity(result.confidence)} - {result.parameter}")
                lines.append(f"    URL: {result.url}")
                lines.append(f"    Parameter: {result.parameter}")
                lines.append(f"    Payload: {result.payload}")
                lines.append(f"    Type: {result.payload_type}")
                lines.append(f"    Database: {result.db_type}")
                lines.append(f"    Confidence: {result.confidence}%")
                lines.append(f"    Response Code: {result.response_code}")
                lines.append(f"    Response Time: {result.response_time:.3f}s")
                lines.append(f"    Evidence: {result.evidence[:100]}")
        else:
            lines.append("-" * 70)
            lines.append("NO VULNERABILITIES FOUND")
            lines.append("-" * 70)
            lines.append("")
            lines.append("The scan did not detect any SQL injection vulnerabilities.")
            lines.append("This does not guarantee the target is secure.")
            lines.append("Consider manual testing for edge cases.")
        
        lines.append("")
        lines.append("=" * 70)
        lines.append("END OF REPORT")
        lines.append("=" * 70)
        
        content = "\n".join(lines)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return output_file
    
    def _format_result(self, result: ScanResult) -> Dict[str, Any]:
        """Format a single result for JSON output"""
        return {
            "url": result.url,
            "parameter": result.parameter,
            "payload": result.payload,
            "payload_type": result.payload_type,
            "severity": self._get_severity(result.confidence),
            "confidence": result.confidence,
            "database_type": result.db_type,
            "error_type": result.error_type,
            "evidence": result.evidence,
            "response": {
                "status_code": result.response_code,
                "time_seconds": round(result.response_time, 3),
                "length_bytes": result.response_length,
            }
        }
    
    def _get_severity(self, confidence: int) -> str:
        """Map confidence to severity level"""
        if confidence >= 90:
            return "CRITICAL"
        elif confidence >= 70:
            return "HIGH"
        elif confidence >= 50:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _get_unique_params(self) -> List[str]:
        """Get list of unique vulnerable parameters"""
        return list(set(r.parameter for r in self.results))
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate vulnerability summary statistics"""
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        by_database: Dict[str, int] = {}
        by_injection_type: Dict[str, int] = {}
        
        for result in self.results:
            severity = self._get_severity(result.confidence).lower()
            by_severity[severity] = by_severity.get(severity, 0) + 1
            
            by_database[result.db_type] = by_database.get(result.db_type, 0) + 1
            
            by_injection_type[result.payload_type] = by_injection_type.get(result.payload_type, 0) + 1
        
        return {
            "by_severity": by_severity,
            "by_database": by_database,
            "by_injection_type": by_injection_type,
        }
    
    def print_summary(self) -> None:
        """Print a summary to console"""
        print("\n" + "=" * 60)
        print("SCAN SUMMARY")
        print("=" * 60)
        print(f"Target: {self.target_url}")
        print(f"Vulnerabilities Found: {len(self.results)}")
        print(f"Unique Parameters: {len(self._get_unique_params())}")
        print(f"Scan Duration: {self.progress.elapsed_time:.2f}s")
        
        if self.results:
            print("\nVulnerable Parameters:")
            for param in self._get_unique_params():
                param_results = [r for r in self.results if r.parameter == param]
                max_conf = max(r.confidence for r in param_results)
                print(f"  - {param} (confidence: {max_conf}%)")
        
        print("=" * 60)


def generate_reports(
    results: List[ScanResult],
    progress: ScanProgress,
    target_url: str,
    json_output: str = "scan_results.json",
    txt_output: str = "scan_results.txt"
) -> tuple:
    """Convenience function to generate both report types"""
    generator = ReportGenerator(results, progress, target_url)
    
    json_file = generator.generate_json(json_output)
    txt_file = generator.generate_txt(txt_output)
    
    generator.print_summary()
    
    return json_file, txt_file
