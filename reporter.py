from jinja2 import Template
import os, datetime

TPL = """<!doctype html><html><head><meta charset=utf-8>
<title>Recon Report {{r.target}}</title>
<style>
body{font:14px monospace;background:#0e0e10;color:#d6d6d6;margin:0;padding:20px}
h1{color:#fff}h2{color:#9aa7ff;border-bottom:1px solid #2a2a3a;padding-bottom:4px}
table{border-collapse:collapse;width:100%;margin-top:8px}
th,td{border:1px solid #2a2a3a;padding:8px;text-align:left;vertical-align:top;font-size:13px}
th{background:#16161c;color:#9aa7ff}
.sev{font-weight:bold;padding:2px 8px;border-radius:3px;display:inline-block}
.critical{background:#8b0000;color:#fff}
.high{background:#c33;color:#fff}
.medium{background:#e83;color:#111}
.low{background:#666;color:#fff}
.info{background:#2a4;color:#fff}
ul.expl{margin:0;padding-left:16px}
ul.expl li{margin:1px 0}
details{margin-top:8px}
summary{cursor:pointer;color:#9aa7ff}
</style></head><body>
<h1>{{r.target}}</h1><p>Generated: {{ts}}</p>

<h2>Open ports ({{r.open_ports|length}})</h2>
<table><tr><th>Port</th><th>Service</th></tr>
{% for p in r.open_ports %}<tr><td>{{p.port}}</td><td>{{p.service}}</td></tr>{% endfor %}
</table>

<h2>Subdomains ({{r.subdomains|length}})</h2>
<table><tr><th>Host</th><th>IP</th></tr>
{% for k,v in r.subdomains.items() %}<tr><td class="mono">{{k}}</td><td>{{v}}</td></tr>{% endfor %}
</table>

<h2>Findings ({{r.findings|length}})</h2>
<table>
<tr><th>Severity</th><th>CVSS</th><th>Kind</th><th>URL</th><th>Param</th>
<th>Payload</th><th>Evidence</th><th>Risk</th><th>Exploited</th><th>Exploit surface</th></tr>
{% for f in r.findings %}
<tr class="{{f.severity}}">
  <td><span class="sev {{f.severity}}">{{f.severity|upper}}</span></td>
  <td>{{f.cvss if f.cvss is not none else ''}}</td>
  <td>{{f.kind}}</td>
  <td class="mono">{{f.url}}</td>
  <td class="mono">{{f.param}}</td>
  <td class="mono">{{f.payload}}</td>
  <td>{{f.evidence}}</td>
  <td>{{f.risk}}</td>
  <td>{{f.exploited}}</td>
  <td>
    {% if f.exploits %}
    <details><summary>{{f.exploits|length}} technique(s)</summary>
      <ul class="expl">{% for e in f.exploits %}<li>{{e}}</li>{% endfor %}</ul>
    </details>
    {% endif %}
  </td>
</tr>
{% endfor %}
</table>
</body></html>"""

def render(report, out):
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    html = Template(TPL).render(r=report, ts=ts)
    with open(out, "w") as fh:
        fh.write(html)
    return os.path.abspath(out)
