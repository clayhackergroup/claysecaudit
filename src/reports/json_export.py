"""JSON report export"""
import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional

class JSONReporter:
    """Generate JSON reports"""

    def __init__(self, output_dir: str = "/var/lib/clay-sec-audit/reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate_report(
        self,
        scan_results: Dict[str, Any],
        overall_score: float,
        audit_id: str
    ) -> str:
        """Generate JSON report"""
        
        report = {
            "audit_id": audit_id,
            "timestamp": datetime.now().isoformat(),
            "system_info": {
                "hostname": scan_results.get("hostname", "unknown"),
                "platform": scan_results.get("platform", "linux"),
                "kernel": scan_results.get("kernel", "unknown")
            },
            "security_score": overall_score,
            "summary": {
                "total_findings": self._count_findings(scan_results),
                "critical": self._count_by_severity(scan_results, "critical"),
                "high": self._count_by_severity(scan_results, "high"),
                "medium": self._count_by_severity(scan_results, "medium"),
                "low": self._count_by_severity(scan_results, "low")
            },
            "scanners": {}
        }

        # Add scanner results
        for scanner_name, results in scan_results.items():
            if scanner_name not in ["hostname", "platform", "kernel"]:
                if isinstance(results, dict) and "findings" in results:
                    report["scanners"][scanner_name] = {
                        "findings": results.get("findings", []),
                        "total_findings": len(results.get("findings", [])),
                        "severity_score": results.get("severity_score", {})
                    }

        # Save report
        report_file = os.path.join(self.output_dir, f"report_{audit_id}.json")
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)

        return report_file

    def _count_findings(self, scan_results: Dict) -> int:
        """Count total findings"""
        total = 0
        for key, value in scan_results.items():
            if isinstance(value, dict) and "findings" in value:
                total += len(value.get("findings", []))
        return total

    def _count_by_severity(self, scan_results: Dict, severity: str) -> int:
        """Count findings by severity"""
        count = 0
        for key, value in scan_results.items():
            if isinstance(value, dict) and "findings" in value:
                for finding in value.get("findings", []):
                    if isinstance(finding, dict) and finding.get("severity") == severity:
                        count += 1
        return count
