import os
from datetime import datetime
from typing import List
from jinja2 import Template
from weasyprint import HTML
from app.models import Scan, Finding, Recommendation
from app.pq_score import get_top_findings, estimate_effort


def generate_pdf_report(scan: Scan, findings: List[Finding], recommendations: List[Recommendation], output_path: str):
    """Generate PDF executive summary report"""
    
    # Get PQ score and level
    from app.pq_score import calculate_pq_score
    pq_score, pq_level = calculate_pq_score(findings)
    
    # Get top findings
    top_findings = get_top_findings(findings, limit=3)
    
    # Get top P0 recommendations
    top_recommendations = sorted(
        [r for r in recommendations if r.priority.value == "P0"],
        key=lambda x: x.confidence_score,
        reverse=True
    )[:3]
    if len(top_recommendations) < 3:
        # Add P1 if not enough P0
        p1_recs = sorted(
            [r for r in recommendations if r.priority.value == "P1"],
            key=lambda x: x.confidence_score,
            reverse=True
        )[:3 - len(top_recommendations)]
        top_recommendations.extend(p1_recs)
    
    # Estimate effort
    effort = estimate_effort(pq_score, len(findings))
    
    # Count findings by severity
    severity_counts = {
        "P0": sum(1 for f in findings if f.severity.value == "P0"),
        "P1": sum(1 for f in findings if f.severity.value == "P1"),
        "P2": sum(1 for f in findings if f.severity.value == "P2"),
        "P3": sum(1 for f in findings if f.severity.value == "P3"),
    }
    
    # HTML template
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <style>
            body {
                font-family: Arial, sans-serif;
                margin: 40px;
                color: #333;
            }
            .header {
                border-bottom: 3px solid #0066cc;
                padding-bottom: 20px;
                margin-bottom: 30px;
            }
            h1 {
                color: #0066cc;
                margin: 0;
            }
            .metadata {
                color: #666;
                font-size: 14px;
                margin-top: 10px;
            }
            .score-section {
                background: #f5f5f5;
                padding: 20px;
                border-radius: 8px;
                margin: 20px 0;
            }
            .score-value {
                font-size: 48px;
                font-weight: bold;
                color: {% if pq_level == 'Critical' %}#d32f2f{% elif pq_level == 'High' %}#f57c00{% elif pq_level == 'Medium' %}#fbc02d{% else %}#388e3c{% endif %};
                margin: 10px 0;
            }
            .score-level {
                font-size: 24px;
                color: #666;
            }
            .summary-grid {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 20px;
                margin: 20px 0;
            }
            .summary-box {
                background: white;
                padding: 15px;
                border-left: 4px solid #0066cc;
                border-radius: 4px;
            }
            .summary-box h3 {
                margin: 0 0 10px 0;
                color: #0066cc;
            }
            .findings-section {
                margin: 30px 0;
            }
            .finding-item {
                background: #fff;
                padding: 15px;
                margin: 10px 0;
                border-radius: 4px;
            }
            .finding-item-p0 { border-left: 4px solid #d32f2f; }
            .finding-item-p1 { border-left: 4px solid #f57c00; }
            .finding-item-p2 { border-left: 4px solid #fbc02d; }
            .finding-item-p3 { border-left: 4px solid #388e3c; }
            .finding-severity {
                display: inline-block;
                padding: 4px 8px;
                border-radius: 4px;
                font-weight: bold;
                font-size: 12px;
                margin-right: 10px;
            }
            .severity-p0 { background: #d32f2f; color: white; }
            .severity-p1 { background: #f57c00; color: white; }
            .severity-p2 { background: #fbc02d; color: #333; }
            .severity-p3 { background: #388e3c; color: white; }
            .recommendations {
                background: #e3f2fd;
                padding: 20px;
                border-radius: 8px;
                margin: 20px 0;
            }
            .recommendations h2 {
                color: #0066cc;
                margin-top: 0;
            }
            .footer {
                margin-top: 40px;
                padding-top: 20px;
                border-top: 1px solid #ddd;
                color: #666;
                font-size: 12px;
                text-align: center;
            }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Cryptography Vulnerability Scan Report</h1>
            <div class="metadata">
                <strong>Target:</strong> {{ target }}<br>
                <strong>Scan Date:</strong> {{ scan_date }}<br>
                <strong>Scan ID:</strong> #{{ scan_id }}
            </div>
        </div>
        
        <div class="score-section">
            <div class="score-value">{{ pq_score }}</div>
            <div class="score-level">{{ pq_level }} Risk</div>
        </div>
        
        <div class="summary-grid">
            <div class="summary-box">
                <h3>Findings Summary</h3>
                <p><strong>Total Findings:</strong> {{ total_findings }}</p>
                <p><strong>Critical (P0):</strong> {{ severity_counts.P0 }}</p>
                <p><strong>High (P1):</strong> {{ severity_counts.P1 }}</p>
                <p><strong>Medium (P2):</strong> {{ severity_counts.P2 }}</p>
                <p><strong>Low (P3):</strong> {{ severity_counts.P3 }}</p>
            </div>
            <div class="summary-box">
                <h3>Remediation Estimate</h3>
                <p><strong>Effort:</strong> {{ effort }}</p>
                <p><strong>Priority:</strong> {{ pq_level }}</p>
            </div>
        </div>
        
        <div class="findings-section">
            <h2>Top Findings</h2>
            {% for finding in top_findings %}
            <div class="finding-item finding-item-{{ finding.severity|lower }}">
                <span class="finding-severity severity-{{ finding.severity|lower }}">{{ finding.severity }}</span>
                <strong>{{ finding.category }}</strong>
                <p>{{ finding.evidence }}</p>
            </div>
            {% endfor %}
        </div>
        
        <div class="recommendations">
            <h2>Top Recommendations (P0 Priority)</h2>
            {% for rec in top_recommendations %}
            <div style="background: white; padding: 15px; margin: 10px 0; border-radius: 4px; border-left: 4px solid {% if rec.priority == 'P0' %}#d32f2f{% elif rec.priority == 'P1' %}#f57c00{% else %}#fbc02d{% endif %};">
                <p><strong>[{{ rec.priority }}] {{ rec.short_description }}</strong></p>
                <p><strong>Effort:</strong> {{ rec.effort_estimate }} | <strong>Confidence:</strong> {{ rec.confidence_score }}%</p>
                <details style="margin-top: 10px;">
                    <summary style="cursor: pointer; font-weight: bold;">Technical Steps</summary>
                    <pre style="background: #f5f5f5; padding: 10px; margin-top: 5px; white-space: pre-wrap; font-size: 11px;">{{ rec.technical_steps }}</pre>
                </details>
            </div>
            {% endfor %}
            {% if recommendations|length > 3 %}
            <p style="margin-top: 15px; font-style: italic;">... and {{ recommendations|length - 3 }} more recommendations. See full report for details.</p>
            {% endif %}
        </div>
        
        <div class="footer">
            <p>Generated by Cryptography Vulnerability Scanner on {{ generated_at }}</p>
            <p>This report contains sensitive security information. Handle with care.</p>
        </div>
    </body>
    </html>
    """
    
    # Render template
    template = Template(html_template)
    html_content = template.render(
        target=scan.target,
        scan_date=scan.created_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
        scan_id=scan.id,
        pq_score=int(pq_score),
        pq_level=pq_level,
        total_findings=len(findings),
        severity_counts=severity_counts,
        top_findings=top_findings,
        top_recommendations=top_recommendations,
        recommendations=recommendations,
        effort=effort,
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    )
    
    # Generate PDF
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    HTML(string=html_content).write_pdf(output_path)
    
    return output_path

