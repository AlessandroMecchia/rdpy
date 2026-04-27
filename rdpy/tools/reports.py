import argparse
import os
from html import escape
from pathlib import Path

from rdpy.tools.common import load_json


SEVERITY_ORDER = {
    "high": 0,
    "medium": 1,
    "warning": 2,
    "info": 3,
    "low": 4,
}


def count_where(results, predicate):
    return sum(1 for item in results if predicate(item))


def css_token(value):
    return str(value).lower().replace("_", "-").replace(" ", "-")


def badge(value, kind=None):
    if value in (None, ""):
        value = "unknown"

    class_name = css_token(kind or value)
    return f'<span class="badge badge-{escape(class_name)}">{escape(str(value))}</span>'


def bool_badge(value, true_label, false_label):
    if value is True:
        return badge(true_label, "good")
    if value is False:
        return badge(false_label, "bad")
    return badge("unknown", "unknown")


def format_ms(value):
    if value is None:
        return "-"
    return f"{float(value):.2f}"


def target_name(item):
    return f"{item.get('host', '')}:{item.get('port', '')}"


def render_recommendations(item):
    recommendations = item.get("recommendations", [])

    if not recommendations:
        return '<span class="muted">None</span>'

    rows = []
    for rec in recommendations:
        priority = rec.get("priority", "low")
        finding = rec.get("finding", "")
        recommendation = rec.get("recommendation", "")
        rows.append(
            "<li>"
            f"{badge(priority, priority)} "
            f"<strong>{escape(finding)}</strong>"
            f"<span>{escape(recommendation)}</span>"
            "</li>"
        )

    return '<ul class="recommendations">' + "".join(rows) + "</ul>"


def render_table(results):
    rows = []
    sorted_results = sorted(
        results,
        key=lambda item: (
            -item.get("risk", {}).get("score", 0),
            target_name(item),
        ),
    )

    for item in sorted_results:
        risk = item.get("risk", {})
        policy = item.get("policy", {})
        risk_level = risk.get("level", "unknown")
        risk_score = risk.get("score", 0)
        policy_status = policy.get("status", "unknown")

        rows.append(f"""
        <tr class="risk-row-{escape(css_token(risk_level))}">
            <td class="target"><strong>{escape(str(item.get("host", "")))}</strong><span>:{escape(str(item.get("port", "")))}</span></td>
            <td>{badge(item.get("status", "unknown"))}</td>
            <td>{bool_badge(item.get("rdp_detected"), "yes", "no")}</td>
            <td>{escape(str(item.get("selected_protocol") or "-"))}</td>
            <td>{bool_badge(item.get("nla_required"), "required", "not required")}</td>
            <td>{bool_badge(item.get("tls_supported"), "detected", "not detected")}</td>
            <td class="number">{format_ms(item.get("response_time_ms"))}</td>
            <td>{badge(risk_level, risk_level)} <span class="score">{escape(str(risk_score))}</span></td>
            <td>{badge(policy_status, policy_status)}</td>
            <td class="recommendation-cell">{render_recommendations(item)}</td>
        </tr>
        """)

    return "\n".join(rows)


def render_changes(changes):
    if not changes:
        return '<p class="empty">No baseline changes provided or no changes detected.</p>'

    rows = []
    sorted_changes = sorted(
        changes,
        key=lambda item: (
            SEVERITY_ORDER.get(item.get("severity"), 99),
            item.get("target", ""),
            item.get("field", ""),
        ),
    )

    for change in sorted_changes:
        rows.append(f"""
        <tr>
            <td class="target"><strong>{escape(str(change.get("target", "")))}</strong></td>
            <td>{escape(str(change.get("message", "")))}</td>
            <td>{badge(change.get("severity", "info"), change.get("severity", "info"))}</td>
            <td>{escape(str(change.get("field", "-")))}</td>
            <td>{escape(str(change.get("before", "-")))}</td>
            <td>{escape(str(change.get("after", "-")))}</td>
        </tr>
        """)

    return f"""
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>Target</th>
                    <th>Change</th>
                    <th>Severity</th>
                    <th>Field</th>
                    <th>Before</th>
                    <th>After</th>
                </tr>
            </thead>
            <tbody>{''.join(rows)}</tbody>
        </table>
    </div>
    """


def image_src(image, output_path):
    if not output_path:
        return image.as_posix()

    report_dir = Path(output_path).resolve().parent
    relative = os.path.relpath(image.resolve(), report_dir)
    return Path(relative).as_posix()


def render_plots(plot_dir, output_path=None):
    if not plot_dir:
        return '<p class="empty">No plots provided. Generate them with <code>rdpy-visualize</code> and rerun this report with <code>--plots</code>.</p>'

    plot_path = Path(plot_dir)

    if not plot_path.exists():
        return f'<p class="empty">Plots directory not found: <code>{escape(str(plot_dir))}</code></p>'

    images = sorted(plot_path.glob("*.png"))

    if not images:
        return f'<p class="empty">No PNG plots found in <code>{escape(str(plot_dir))}</code>.</p>'

    cards = []
    for image in images:
        title = image.stem.replace("_", " ").title()
        cards.append(f"""
        <section class="plot">
            <h3>{escape(title)}</h3>
            <a href="{escape(image_src(image, output_path))}">
                <img src="{escape(image_src(image, output_path))}" alt="{escape(title)}">
            </a>
        </section>
        """)

    return '<div class="plot-grid">' + "\n".join(cards) + "</div>"


def render_key_findings(results, changes):
    findings = []

    for item in results:
        policy_status = item.get("policy", {}).get("status")
        risk = item.get("risk", {})
        if policy_status == "fail":
            findings.append(
                f"{target_name(item)} fails policy with risk score {risk.get('score', 0)}."
            )
        elif risk.get("level") == "high":
            findings.append(
                f"{target_name(item)} is high risk with score {risk.get('score', 0)}."
            )

    for change in changes:
        if change.get("severity") == "high":
            findings.append(f"{change.get('target')}: {change.get('message')}.")

    if not findings:
        return '<p class="empty">No high-priority findings in this data set.</p>'

    rows = "".join(f"<li>{escape(finding)}</li>" for finding in findings[:8])
    return f'<ul class="findings">{rows}</ul>'


def generate_report(results, changes=None, plot_dir=None, output_path=None):
    changes = changes or []

    total = len(results)
    open_count = count_where(results, lambda item: item.get("status") == "open")
    rdp_detected = count_where(results, lambda item: item.get("rdp_detected") is True)
    policy_fail = count_where(results, lambda item: item.get("policy", {}).get("status") == "fail")
    policy_warning = count_where(results, lambda item: item.get("policy", {}).get("status") == "warning")
    high_risk = count_where(results, lambda item: item.get("risk", {}).get("level") == "high")
    highest_score = max([item.get("risk", {}).get("score", 0) for item in results] or [0])

    return f"""<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>RDP Defense Report</title>
    <style>
        :root {{
            --bg: #f7f8fa;
            --panel: #ffffff;
            --text: #20242a;
            --muted: #667085;
            --line: #d9dee8;
            --header: #2f343d;
            --good: #207245;
            --bad: #b42318;
            --warn: #a15c07;
            --info: #245b96;
        }}
        * {{ box-sizing: border-box; }}
        body {{
            margin: 0;
            background: var(--bg);
            color: var(--text);
            font-family: Arial, Helvetica, sans-serif;
            line-height: 1.45;
        }}
        .page {{
            max-width: 1280px;
            margin: 0 auto;
            padding: 32px 24px 48px;
        }}
        header {{
            background: var(--header);
            color: white;
            padding: 24px;
            border-radius: 8px;
            margin-bottom: 24px;
        }}
        h1, h2, h3 {{ margin: 0; }}
        h1 {{ font-size: 30px; }}
        h2 {{ font-size: 20px; margin: 28px 0 12px; }}
        h3 {{ font-size: 15px; margin-bottom: 12px; }}
        .subtitle {{ color: #d6dae1; margin-top: 8px; }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
            gap: 12px;
        }}
        .card, .plot {{
            background: var(--panel);
            border: 1px solid var(--line);
            border-radius: 8px;
        }}
        .card {{
            padding: 14px 16px;
        }}
        .metric {{
            color: var(--muted);
            font-size: 13px;
            margin-bottom: 6px;
        }}
        .value {{
            font-size: 28px;
            font-weight: 700;
        }}
        .table-wrap {{
            overflow-x: auto;
            background: var(--panel);
            border: 1px solid var(--line);
            border-radius: 8px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}
        th, td {{
            border-bottom: 1px solid var(--line);
            padding: 10px 12px;
            text-align: left;
            vertical-align: top;
        }}
        th {{
            background: #eef1f5;
            color: #343a44;
            font-size: 12px;
            letter-spacing: .02em;
            text-transform: uppercase;
            white-space: nowrap;
        }}
        tr:last-child td {{ border-bottom: 0; }}
        .target span, .muted {{ color: var(--muted); }}
        .number, .score {{ font-variant-numeric: tabular-nums; }}
        .score {{
            display: inline-block;
            margin-left: 6px;
            color: var(--muted);
            font-weight: 700;
        }}
        .badge {{
            display: inline-flex;
            align-items: center;
            min-height: 22px;
            padding: 2px 8px;
            border-radius: 999px;
            border: 1px solid #ccd3dd;
            background: #f3f5f8;
            color: #344054;
            font-size: 12px;
            font-weight: 700;
            white-space: nowrap;
        }}
        .badge-good, .badge-pass, .badge-low, .badge-info {{
            border-color: #b8dfca;
            background: #eaf7ef;
            color: var(--good);
        }}
        .badge-bad, .badge-fail, .badge-high {{
            border-color: #f0b7b2;
            background: #fff0ee;
            color: var(--bad);
        }}
        .badge-medium, .badge-warning {{
            border-color: #efd09a;
            background: #fff7e8;
            color: var(--warn);
        }}
        .badge-open {{
            border-color: #b8cdec;
            background: #eef5ff;
            color: var(--info);
        }}
        .badge-closed-or-unreachable, .badge-unknown {{
            border-color: #d5dae3;
            background: #f5f6f8;
            color: var(--muted);
        }}
        .recommendation-cell {{
            min-width: 300px;
            max-width: 440px;
        }}
        .recommendations, .findings {{
            margin: 0;
            padding-left: 18px;
        }}
        .recommendations li {{
            margin-bottom: 8px;
        }}
        .recommendations li:last-child {{
            margin-bottom: 0;
        }}
        .recommendations span:not(.badge) {{
            display: block;
            margin-top: 3px;
            color: var(--muted);
        }}
        .plot-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(360px, 1fr));
            gap: 16px;
        }}
        .plot {{
            padding: 14px;
        }}
        .plot img {{
            display: block;
            width: 100%;
            height: auto;
            border: 1px solid var(--line);
            border-radius: 6px;
            background: white;
        }}
        .empty {{
            background: var(--panel);
            border: 1px dashed #b8c0cc;
            border-radius: 8px;
            color: var(--muted);
            padding: 14px;
        }}
        code {{
            background: #eef1f5;
            border-radius: 4px;
            padding: 2px 5px;
        }}
        @media (max-width: 720px) {{
            .page {{ padding: 18px 12px 32px; }}
            header {{ padding: 18px; }}
            h1 {{ font-size: 24px; }}
            .plot-grid {{ grid-template-columns: 1fr; }}
        }}
    </style>
</head>
<body>
    <main class="page">
        <header>
            <h1>RDP Defense Report</h1>
            <p class="subtitle">Audit summary, policy status, baseline changes, and generated plots.</p>
        </header>

        <section class="summary">
            <div class="card"><div class="metric">Hosts analyzed</div><div class="value">{total}</div></div>
            <div class="card"><div class="metric">RDP reachable</div><div class="value">{open_count}</div></div>
            <div class="card"><div class="metric">RDP detected</div><div class="value">{rdp_detected}</div></div>
            <div class="card"><div class="metric">Policy failures</div><div class="value">{policy_fail}</div></div>
            <div class="card"><div class="metric">Policy warnings</div><div class="value">{policy_warning}</div></div>
            <div class="card"><div class="metric">High risk hosts</div><div class="value">{high_risk}</div></div>
            <div class="card"><div class="metric">Highest risk score</div><div class="value">{highest_score}</div></div>
        </section>

        <h2>Key Findings</h2>
        {render_key_findings(results, changes)}

        <h2>Audit Results</h2>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Target</th>
                        <th>Status</th>
                        <th>RDP</th>
                        <th>Protocol</th>
                        <th>NLA</th>
                        <th>TLS</th>
                        <th>Response ms</th>
                        <th>Risk</th>
                        <th>Policy</th>
                        <th>Recommendations</th>
                    </tr>
                </thead>
                <tbody>
                    {render_table(results)}
                </tbody>
            </table>
        </div>

        <h2>Baseline Changes</h2>
        {render_changes(changes)}

        <h2>Plots</h2>
        {render_plots(plot_dir, output_path)}

        <h2>Limitations</h2>
        <ul class="findings">
            <li>This tool performs authorized defensive checks only.</li>
            <li>The risk score is configurable and does not prove exploitability.</li>
            <li>NLA and TLS detection are best-effort and may be reported as unknown.</li>
            <li>No brute force, MITM, exploit, or honeypot behavior is implemented.</li>
        </ul>
    </main>
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

    output = Path(args.out)
    html = generate_report(results, changes, args.plots, output)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html, encoding="utf-8")

    print(f"Report written to {args.out}")


if __name__ == "__main__":
    main()
