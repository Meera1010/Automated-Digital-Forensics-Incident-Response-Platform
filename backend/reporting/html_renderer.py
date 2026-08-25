"""
ADFIR Platform — HTML Report Renderer
=========================================
Renders an incident forensic report to HTML using Jinja2 templates.
"""
import os
from jinja2 import Environment, FileSystemLoader

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")

def render_html(context: dict) -> str:
    """
    Renders the forensic report into HTML using the report_template.html Jinja2 template.
    """
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR), autoescape=True)
    template = env.get_template("report_template.html")
    return template.render(**context)
