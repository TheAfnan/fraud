import re
import subprocess
import sys
from pathlib import Path

# Add project root
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend.security import redact_sensitive_text

def convert_md_to_pdf():
    md_path = Path(r"C:\Users\afnan\.gemini\antigravity\brain\f2d61920-de01-4273-93d3-81bc68517149\project_progress_report.md")
    if not md_path.exists():
        raise FileNotFoundError(f"Markdown report not found at {md_path}")

    with open(md_path, "r", encoding="utf-8") as f:
        lines = [redact_sensitive_text(l) for l in f.readlines()]

    html = []
    html.append("""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>TigerGraph Agentic Fraud Investigation System - Technical Report</title>
<style>
  @page {
    size: A4;
    margin: 16mm 16mm 16mm 16mm;
  }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    color: #1e293b;
    line-height: 1.5;
    font-size: 12.5px;
  }
  .header {
    border-bottom: 3px solid #2563eb;
    padding-bottom: 10px;
    margin-bottom: 16px;
  }
  h1 {
    font-size: 20px;
    color: #0f172a;
    margin: 0 0 6px 0;
  }
  .subtitle {
    font-size: 13px;
    color: #475569;
    margin: 0 0 10px 0;
  }
  .badges {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
  }
  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 9999px;
    font-size: 10.5px;
    font-weight: 600;
  }
  .badge-blue { background-color: #dbeafe; color: #1d4ed8; }
  .badge-green { background-color: #dcfce7; color: #15803d; }
  .badge-purple { background-color: #f3e8ff; color: #7e22ce; }
  .badge-amber { background-color: #fef3c7; color: #b45309; }

  h2 {
    font-size: 15px;
    color: #1e3a8a;
    border-bottom: 1px solid #cbd5e1;
    padding-bottom: 4px;
    margin-top: 20px;
    margin-bottom: 8px;
    page-break-after: avoid;
  }
  h3 {
    font-size: 13.5px;
    color: #0f172a;
    margin-top: 14px;
    margin-bottom: 6px;
    page-break-after: avoid;
  }
  p, li {
    color: #334155;
    margin-top: 3px;
    margin-bottom: 4px;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    margin: 12px 0;
    font-size: 11.5px;
    page-break-inside: avoid;
  }
  th, td {
    border: 1px solid #cbd5e1;
    padding: 5px 8px;
    text-align: left;
  }
  th {
    background-color: #f1f5f9;
    font-weight: 700;
    color: #0f172a;
  }
  tr:nth-child(even) {
    background-color: #f8fafc;
  }
  pre {
    background-color: #0f172a;
    color: #f8fafc;
    padding: 8px 10px;
    border-radius: 5px;
    font-family: Consolas, 'Courier New', monospace;
    font-size: 10.5px;
    overflow-x: auto;
    page-break-inside: avoid;
    line-height: 1.4;
  }
  code {
    font-family: Consolas, 'Courier New', monospace;
    font-size: 11px;
    background: #f1f5f9;
    color: #b91c1c;
    padding: 1px 3px;
    border-radius: 3px;
  }
  pre code {
    background: transparent;
    color: inherit;
    padding: 0;
  }
  blockquote {
    background: #eff6ff;
    border-left: 4px solid #2563eb;
    margin: 8px 0;
    padding: 6px 12px;
    color: #1e40af;
    page-break-inside: avoid;
  }
  strong {
    color: #0f172a;
  }
  ul, ol {
    margin: 4px 0;
    padding-left: 20px;
  }
  li {
    margin-bottom: 3px;
  }
</style>
</head>
<body>
""")

    in_pre = False
    in_table = False
    table_header = False

    def fmt_inline(txt):
        txt = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", txt)
        txt = re.sub(r"`([^`]+)`", r"<code>\1</code>", txt)
        return txt

    for line in lines:
        stripped = line.rstrip()
        if stripped.startswith("```"):
            if in_pre:
                html.append("</code></pre>\n")
                in_pre = False
            else:
                html.append("<pre><code>")
                in_pre = True
            continue
        if in_pre:
            clean = stripped.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            html.append(clean + "\n")
            continue

        # Tables
        if "|" in stripped and stripped.startswith("|") and stripped.endswith("|"):
            cells = [c.strip() for c in stripped[1:-1].split("|")]
            if all(re.match(r"^:?-+:?$", c) for c in cells):
                continue
            if not in_table:
                html.append("<table>\n")
                in_table = True
                table_header = True
            row_tag = "th" if table_header else "td"
            html.append("  <tr>" + "".join(f"<{row_tag}>{fmt_inline(c)}</{row_tag}>" for c in cells) + "</tr>\n")
            table_header = False
            continue
        else:
            if in_table:
                html.append("</table>\n")
                in_table = False

        if not stripped:
            continue
        if stripped.startswith("# "):
            html.append(f"""
            <div class="header">
              <h1>{fmt_inline(stripped[2:])}</h1>
              <div class="badges">
                <span class="badge badge-green">AUTHORITATIVE BACKEND: TIGERGRAPH LIVE</span>
                <span class="badge badge-blue">SAVANNA CLOUD v4.2.5 (AWS US-EAST-1)</span>
                <span class="badge badge-purple">DATASET: IEEE-CIS (590K TXNS)</span>
                <span class="badge badge-amber">PHASE 1: 100% OK / ALL PASSED</span>
              </div>
            </div>
            """)
        elif stripped.startswith("## "):
            html.append(f"<h2>{fmt_inline(stripped[3:])}</h2>\n")
        elif stripped.startswith("### "):
            html.append(f"<h3>{fmt_inline(stripped[4:])}</h3>\n")
        elif stripped.startswith("> "):
            html.append(f"<blockquote>{fmt_inline(stripped[2:])}</blockquote>\n")
        elif stripped.startswith("- ") or stripped.startswith("* "):
            html.append(f"<ul><li>{fmt_inline(stripped[2:])}</li></ul>\n")
        elif re.match(r"^\d+\.\s", stripped):
            m = re.match(r"^\d+\.\s(.*)", stripped)
            html.append(f"<ol><li>{fmt_inline(m.group(1))}</li></ol>\n")
        elif stripped == "---":
            html.append('<hr style="border:0; border-top:1px solid #cbd5e1; margin:14px 0;">\n')
        else:
            html.append(f"<p>{fmt_inline(stripped)}</p>\n")

    if in_table:
        html.append("</table>\n")
    if in_pre:
        html.append("</code></pre>\n")

    html.append("</body></html>")

    tmp_html = Path(r"C:\Users\afnan\Desktop\track5\report_temp.html")
    pdf_out = Path(r"C:\Users\afnan\Desktop\track5\TigerGraph_Agentic_Fraud_Investigation_Report.pdf")

    with open(tmp_html, "w", encoding="utf-8") as f:
        f.write("".join(html))

    print(f"HTML intermediate written: {tmp_html}")

    edge_exe = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
    cmd = [
        edge_exe,
        "--headless=new",
        "--disable-gpu",
        "--run-all-compositor-stages-before-draw",
        f"--print-to-pdf={str(pdf_out.resolve())}",
        "--no-pdf-header-footer",
        str(tmp_html.resolve())
    ]
    subprocess.run(cmd, check=True)
    if pdf_out.exists():
        print(f"SUCCESS: PDF created at {pdf_out} (Size: {pdf_out.stat().st_size} bytes)")
    else:
        print("ERROR: PDF was not generated.")

if __name__ == "__main__":
    convert_md_to_pdf()
