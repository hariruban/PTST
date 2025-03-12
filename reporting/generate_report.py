from jinja2 import Template

def generate_report(data):
    template = Template("""
    <html>
        <head><title>Pentest Report</title></head>
        <body>
            <h1>Scan Report for {{ target }}</h1>
            <h2>Subdomains Found</h2>
            <ul>{% for sub in subdomains %}<li>{{ sub }}</li>{% endfor %}</ul>
            <h2>Open Ports</h2>
            <ul>{% for port in open_ports %}<li>{{ port }}</li>{% endfor %}</ul>
        </body>
    </html>
    """)

    with open("reports/report.html", "w") as f:
        f.write(template.render(data))
