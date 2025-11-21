"""PDF report generation"""
import os
from datetime import datetime
from typing import Dict, Any
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.platypus import KeepTogether


class PDFReporter:
    """Generate PDF security reports"""

    def __init__(self, output_dir: str = "/var/lib/clay-sec-audit/reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.styles = getSampleStyleSheet()
        self._create_custom_styles()

    def _create_custom_styles(self):
        """Create custom styles"""
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=0
        ))

        self.styles.add(ParagraphStyle(
            name='SectionHeading',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#d9534f'),
            spaceAfter=12,
            spaceBefore=12
        ))

    def generate_report(
        self,
        scan_results: Dict[str, Any],
        overall_score: float,
        audit_id: str
    ) -> str:
        """Generate PDF report"""
        
        report_file = os.path.join(self.output_dir, f"report_{audit_id}.pdf")
        doc = SimpleDocTemplate(report_file, pagesize=letter)
        story = []

        # Title
        story.append(Paragraph("Security Audit Report", self.styles['CustomTitle']))
        story.append(Spacer(1, 0.2 * inch))

        # Executive Summary
        summary_data = [
            ["Audit ID", audit_id],
            ["Timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            ["Security Score", f"{overall_score:.1f}/100"],
            ["Status", self._get_status(overall_score)]
        ]
        
        summary_table = Table(summary_data, colWidths=[2*inch, 4*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f5f5f5')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(summary_table)
        story.append(Spacer(1, 0.3 * inch))

        # Findings Summary
        story.append(Paragraph("Security Findings Summary", self.styles['SectionHeading']))
        
        findings_summary = self._build_findings_summary(scan_results)
        findings_table = Table(findings_summary, colWidths=[2*inch, 1*inch])
        findings_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#d9534f')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(findings_table)
        story.append(Spacer(1, 0.3 * inch))

        # Detailed Findings
        story.append(PageBreak())
        story.append(Paragraph("Detailed Findings", self.styles['SectionHeading']))

        for scanner_name, results in scan_results.items():
            if scanner_name not in ["hostname", "platform", "kernel"] and isinstance(results, dict):
                findings = results.get("findings", [])
                if findings:
                    story.append(Paragraph(f"{scanner_name.replace('_', ' ').title()}", 
                                          self.styles['Heading3']))
                    
                    for finding in findings:
                        if isinstance(finding, dict):
                            finding_text = self._format_finding(finding)
                            story.append(finding_text)
                            story.append(Spacer(1, 0.1 * inch))

        # Recommendations
        story.append(PageBreak())
        story.append(Paragraph("Recommendations", self.styles['SectionHeading']))
        
        recommendations = self._build_recommendations(overall_score)
        for rec in recommendations:
            story.append(Paragraph(f"• {rec}", self.styles['Normal']))
        
        story.append(Spacer(1, 0.3 * inch))
        story.append(Paragraph(
            f"<i>Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>",
            self.styles['Normal']
        ))

        # Build PDF
        doc.build(story)
        return report_file

    def _get_status(self, score: float) -> str:
        """Get status based on score"""
        if score >= 80:
            return "Good"
        elif score >= 60:
            return "Fair"
        elif score >= 40:
            return "Poor"
        else:
            return "Critical"

    def _build_findings_summary(self, scan_results: Dict) -> list:
        """Build findings summary table"""
        summary = [["Severity", "Count"]]
        
        severities = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for key, value in scan_results.items():
            if isinstance(value, dict) and "findings" in value:
                for finding in value.get("findings", []):
                    if isinstance(finding, dict):
                        severity = finding.get("severity", "low")
                        if severity in severities:
                            severities[severity] += 1
        
        summary.append(["CRITICAL", str(severities["critical"])])
        summary.append(["HIGH", str(severities["high"])])
        summary.append(["MEDIUM", str(severities["medium"])])
        summary.append(["LOW", str(severities["low"])])
        
        return summary

    def _format_finding(self, finding: Dict) -> Paragraph:
        """Format a finding for PDF"""
        title = finding.get("title", "Unknown Finding")
        severity = finding.get("severity", "low").upper()
        description = finding.get("description", "No description")
        remediation = finding.get("remediation", "Contact administrator")
        
        text = f"""
        <b>{title}</b> [{severity}]<br/>
        <i>Description:</i> {description}<br/>
        <i>Remediation:</i> {remediation}<br/>
        """
        
        return Paragraph(text, self.styles['Normal'])

    def _build_recommendations(self, score: float) -> list:
        """Build recommendations based on score"""
        recommendations = []
        
        if score < 40:
            recommendations.append("Critical security issues detected. Immediate action required.")
            recommendations.append("Implement emergency patches and configuration fixes")
            recommendations.append("Conduct security incident response procedures")
        
        if score < 60:
            recommendations.append("Review and fix all high-severity findings immediately")
            recommendations.append("Enable security monitoring and alerting")
            recommendations.append("Schedule security assessment with external auditors")
        
        if score < 80:
            recommendations.append("Address medium-severity findings as part of regular maintenance")
            recommendations.append("Implement security training for system administrators")
            recommendations.append("Review security baselines quarterly")
        
        recommendations.append("Schedule regular security audits (quarterly minimum)")
        recommendations.append("Implement automated vulnerability scanning")
        recommendations.append("Maintain detailed audit logs and monitoring")
        
        return recommendations
