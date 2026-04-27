import argparse
from html import escape
from pathlib import Path

from rdpy.tools.common import load_json


def count_where(results, predicate):
    return sum(1 for item in results if predicate(item))


def render_recommendations(item):
    rows = []

    for rec in item.get("recommendations", []):
        rows.append(
            f"<li><strong>{escape(rec.get('priority', ''))}</strong>: "
            f"{escape(rec.get('recommendation', ''))}</li>"
        )

    return "<ul>" + "".join(rows) + "</ul>"


def render_table(results):
    rows = []

    for item in results:
        screenshot = item.get("screenshot")
        screenshot_html = "No"

        if screenshot:
            screenshot_html = f'<a href="{escape(screenshot)}">View</a>'

        rows.append(f"""
        <tr>
            <td>{escape(str(item.get("host", "")))}</td>
            <td>{escape(str(item.get("port", "")))}</td>
            <td>{escape(str(item.get("status", "")))}</td>
            <td>{escape(str(item.get("rdp_detected", "")))}</td>
            <td>{escape(str(item.get("selected_protocol", "")))}</td>
            <td>{escape(str(item.get("nla_required", "")))}</td>
            <td>{escape(str(item.get("tls_supported", "")))}</td>
            <td>{escape(str(item.get("response_time_ms", "")))}</td>
            <td>{escape(str(item.get("risk", {}).get("level", "")))}</td>
            <td>{escape(str(item.get("risk", {}).get("score", "")))}</td>
            <td>{escape(str(item.get("policy", {}).get("status", "")))}</td>
            <td>{screenshot_html}</td>
            <td>{render_recommendations(item)}</td>
        </tr>
        """)

    return "\n".join(rows)


def render_changes(changes):
    if not changes:
        return "<p>No baseline changes provided or no changes detected.</p>"

    rows = []

    for change in changes:
        rows.append(f"""
        <tr>
            <td>{escape(str(change.get("target", "")))}</td>
            <td>{escape(str(change.get("message", "")))}</td>
            <td>{escape(str(change.get("severity", "")))}</td>
            <td>{escape(str(change.get("before", "")))}</td>
            <td>{escape(str(change.get("after", "")))}</td>
        </tr>
        """)

    return f"""
    <table>
        <thead>
            <tr>
                <th>Target</th>
                <th>Change</th>
                <th>Severity</th>
                <th>Before</th>
                <th>After</th>
            </tr>
        </thead>
        <tbody>{''.join(rows)}</tbody>
    </table>
    """


def render_plots(plot_dir):
    if not plot_dir:
        return "<p>No plots provided.</p>"

    plot_path = Path(plot_dir)

    if not plot_path.exists():
        return "<p>No plots directory found.</p>"

    images = []

    for image in sorted(plot_path.glob("*.png")):
        images.append(f"""
        <section class="plot">
            <h3>{escape(image.stem.replace("_", " ").title())}</h3>
            <img src="{escape(str(image))}" alt="{escape(image.stem)}">
        </section>
        """)

    return "\n".join(images) if images else "<p>No plot images found.</p>"


def generate_report(results, changes=None, plot_dir=None):
    changes = changes or []

    total = len(results)
    open_count = count_where(results, lambda item: item.get("status") == "open")
    rdp_detected = count_where(results, lambda item: item.get("rdp_detected") is True)
    policy_fail = count_where(results, lambda item: item.get("policy", {}).get("status") == "fail")
    policy_warning = count_where(results, lambda item: item.get("policy", {}).get("status") == "warning")
    highest_score = max([item.get("risk", {}).get("score", 0) for item in results] or [0])

    return f"""
    <!doctype html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>RDP Defense Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 40px;
                line-height: 1.5;
            }}
            table {{
                border-collapse: collapse;
                width: 100%;
                margin-top: 16px;
                margin-bottom: 32px;
                font-size: 14px;
            }}
            th, td {{
                border: 1px solid #ccc;
                padding: 8px;
                vertical-align: top;
            }}
            th {{
                background: #f2f2f2;
            }}
            img {{
                max-width: 900px;
                width: 100%;
                border: 1px solid #ddd;
                margin-bottom: 24px;
            }}
            .summary {{
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 12px;
                margin-bottom: 24px;
            }}
            .card {{
                border: 1px solid #ccc;
                padding: 12px;
                border-radius: 8px;
                background: #fafafa;
            }}
        </style>
    </head>
    <body>
        <h1>RDP Defense Report</h1>

        <h2>Executive Summary</h2>
        <div class="summary">
            <div class="card"><strong>Hosts analyzed</strong><br>{total}</div>
            <div class="card"><strong>RDP reachable</strong><br>{open_count}</div>
            <div class="card"><strong>RDP detected</strong><br>{rdp_detected}</div>
            <div class="card"><strong>Policy failures</strong><br>{policy_fail}</div>
            <div class="card"><strong>Policy warnings</strong><br>{policy_warning}</div>
            <div class="card"><strong>Highest risk score</strong><br>{highest_score}</div>
        </div>

        <h2>Audit Results</h2>
        <table>
            <thead>
                <tr>
                    <th>Host</th>
                    <th>Port</th>
                    <th>Status</th>
                    <th>RDP detected</th>
                    <th>Protocol</th>
                    <th>NLA</th>
                    <th>TLS</th>
                    <th>Response ms</th>
                    <th>Risk level</th>
                    <th>Risk score</th>
                    <th>Policy</th>
                    <th>Screenshot</th>
                    <th>Recommendations</th>
                </tr>
            </thead>
            <tbody>
                {render_table(results)}
            </tbody>
        </table>

        <h2>Baseline Changes</h2>
        {render_changes(changes)}

        <h2>Plots</h2>
        {render_plots(plot_dir)}

        <h2>Limitations</h2>
        <ul>
            <li>This tool performs authorized defensive checks only.</li>
            <li>The risk score is configurational and does not prove exploitability.</li>
            <li>NLA and TLS detection are best-effort and may be reported as unknown.</li>
            <li>No brute force, MITM, exploit, or honeypot behavior is implemented.</li>
        </ul>
    </body>
    </html>
    """


def main():
    parser = argparse.ArgumentParser(description="Generate an HTML RDP defense report")
    parser.add_argument("input", help="Input current JSON file")
    parser.add_argument("--changes", help="Optional changes JSON file")
    parser.add_argument("--plots", help="Optional plots directory")
    parser.add_argument("--out", default="reports/report.html")

    args = parser.parse_args()

    results = load_json(args.input)
    changes = load_json(args.changes) if args.changes else []

    html = generate_report(results, changes, args.plots)

    output = Path(args.out)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html, encoding="utf-8")

    print(f"Report written to {args.out}")


if __name__ == "__main__":
    main()