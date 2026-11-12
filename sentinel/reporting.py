"""Standalone escaped reports and an explicit metadata-minimized export."""
from copy import deepcopy
from html import escape
import json


def export_report(report, reviews=None, minimize=False):
    reviews = reviews or {}
    if not minimize:
        result = deepcopy(report)
        result['manual_reviews'] = deepcopy(reviews)
        return result
    # Whitelist, rather than attempting to redact arbitrary nested metadata.
    result = {k: deepcopy(report[k]) for k in ('status', 'mode', 'started', 'scanned', 'considered', 'elapsed_seconds') if k in report}
    result['scope'] = 'Omitted for sharing'
    result['sharing'] = 'Paths, identifiers, URLs, fingerprints and detailed coverage omitted. Counts and timestamps remain. Review before sharing.'
    result['limitations'] = ['Candidate detection only. Credential validity and billing are not checked.', 'Detailed coverage is omitted from this sharing copy; consult the local full report.']
    result['findings'] = []
    for i, finding in enumerate(report.get('findings', []), 1):
        item = {k: deepcopy(finding[k]) for k in ('rule', 'severity', 'confidence', 'validity', 'exposure', 'billing') if k in finding}
        item.update(id=f'F{i}', evidence='[REDACTED]', path='Omitted', review=reviews.get(finding['id'], {}).get('status', 'Open'))
        result['findings'].append(item)
    return result


def report_html(report):
    e = lambda value: escape(str(value), quote=True)
    findings = report.get('findings', [])
    reviews = report.get('manual_reviews', {})
    rows = ''.join('<tr>' + ''.join('<td>'+e(v)+'</td>' for v in (
        f.get('severity', ''), f.get('rule', ''), f.get('path', ''), f.get('line', '—'),
        f.get('review', reviews.get(f.get('id'), {}).get('status', 'Open')))) + '</tr>' for f in findings)
    return '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sentinel AI · Security report</title><style>
    body{margin:0;background:#f3f5fa;color:#17233b;font:15px/1.6 system-ui,sans-serif}main{max-width:1080px;margin:40px auto;padding:40px;background:white;border-radius:20px}header{border-bottom:3px solid #ef8a39;padding-bottom:24px}h1{font-size:36px;margin:0}h2{margin-top:32px}small{color:#526078}.metrics{display:flex;gap:18px;flex-wrap:wrap;margin:24px 0}.metric{background:#f3f5fa;padding:18px;border-radius:12px;flex:1}.metric strong{display:block;font-size:26px}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:12px;border-bottom:1px solid #dce2ec;overflow-wrap:anywhere}th{background:#eef2f8}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px}details{margin-top:24px}@media(max-width:600px){main{padding:18px;margin:0}table{font-size:12px}th,td{padding:6px}}@media print{body{background:white}main{margin:0;padding:0}details{display:block}tr{break-inside:avoid}}
    </style></head><body><main><header><small>PERSONAL SECURITY AUDIT / SENTINEL AI</small><h1>Security review report</h1><p>Candidate findings. Credential validity, exploitation and billing are not verified.</p></header>''' + (
        '<div class="metrics"><div class="metric">Scan status<strong>'+e(report.get('status'))+'</strong></div><div class="metric">Items scanned<strong>'+e(report.get('scanned',0))+'</strong></div><div class="metric">Candidates<strong>'+str(len(findings))+'</strong></div></div>'
        '<p><b>Scope:</b> '+e(report.get('scope',''))+'<br><b>Started:</b> '+e(report.get('started',''))+'</p>'
        '<h2>Findings & manual review</h2><p>Manual review labels are user decisions, not verified remediation.</p><table><thead><tr><th>Severity</th><th>Detector</th><th>Location</th><th>Line</th><th>Review</th></tr></thead><tbody>'+rows+'</tbody></table>'
        + ('<p>No candidates detected in the scanned scope. This does not establish that the computer is secure.</p>' if not findings else '')
        + '<h2>Coverage & limitations</h2><ul>'+''.join('<li>'+e(x)+'</li>' for x in report.get('limitations',[]))+'</ul>'
        + '<p>'+e(report.get('sharing','Full report contains filenames and scope metadata. Review before sharing.'))+'</p>'
        + '<details><summary>Complete report data, including redacted evidence</summary><pre>'+e(json.dumps(report,indent=2))+'</pre></details></main></body></html>')
