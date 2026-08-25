"""
ADFIR Platform — PDF Report Renderer
========================================
Converts the HTML report to PDF using WeasyPrint (BSD-3-Clause).

System dependencies required (Ubuntu/Debian):
  apt-get install libcairo2 libpango-1.0-0 libpangocairo-1.0-0
"""
import logging

logger = logging.getLogger(__name__)

def render_pdf(html_content: str) -> bytes:
    """
    Renders the HTML content into a PDF byte array.
    Returns None if WeasyPrint fails (e.g. missing OS dependencies).
    """
    try:
        from weasyprint import HTML
        pdf_bytes = HTML(string=html_content).write_pdf()
        return pdf_bytes
    except Exception as e:
        logger.warning(f"Failed to generate PDF (WeasyPrint OS dependencies might be missing): {e}")
        return None
