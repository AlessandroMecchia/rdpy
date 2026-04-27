import argparse
import os
import tempfile
from collections import Counter
from pathlib import Path

os.environ.setdefault("MPLCONFIGDIR", str(Path(tempfile.gettempdir()) / "rdpy-matplotlib"))

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt

from rdpy.tools.common import load_json


COLORS = {
    "open": "#245b96",
    "closed_or_unreachable": "#8a94a6",
    "low": "#207245",
    "medium": "#a15c07",
    "high": "#b42318",
    "pass": "#207245",
    "warning": "#a15c07",
    "fail": "#b42318",
    "unknown": "#667085",
}

RISK_ORDER = ["low", "medium", "high", "unknown"]
POLICY_ORDER = ["pass", "warning", "fail", "unknown"]
STATUS_ORDER = ["open", "closed_or_unreachable", "unknown"]


def human_label(value):
    return str(value).replace("_", " ").title()


def ordered_counts(results, getter, order):
    counts = Counter(getter(item) or "unknown" for item in results)
    labels = [label for label in order if label in counts]
    labels.extend(sorted(label for label in counts if label not in labels))
    return labels, [counts[label] for label in labels]


def color_for(label):
    return COLORS.get(label, "#476175")


def annotate_bars(ax, bars, horizontal=False):
    for bar in bars:
        if horizontal:
            width = bar.get_width()
            ax.text(
                width + 0.05,
                bar.get_y() + bar.get_height() / 2,
                f"{width:g}",
                va="center",
                ha="left",
                fontsize=9,
                color="#303640",
            )
        else:
            height = bar.get_height()
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                height + 0.05,
                f"{height:g}",
                va="bottom",
                ha="center",
                fontsize=9,
                color="#303640",
            )


def save_bar_chart(labels, values, title, xlabel, ylabel, output_path, horizontal=False):
    labels = labels or ["unknown"]
    values = values or [0]

    if horizontal:
        height = max(4.5, min(14, 1.2 + len(labels) * 0.55))
        fig, ax = plt.subplots(figsize=(11, height))
        bars = ax.barh([human_label(label) for label in labels], values, color=[color_for(label) for label in labels])
        ax.invert_yaxis()
        ax.set_xlabel(xlabel)
        ax.set_ylabel(ylabel)
        annotate_bars(ax, bars, horizontal=True)
        ax.set_xlim(0, max(values) * 1.18 if max(values) else 1)
    else:
        fig, ax = plt.subplots(figsize=(9, 5.5))
        bars = ax.bar([human_label(label) for label in labels], values, color=[color_for(label) for label in labels])
        ax.set_xlabel(xlabel)
        ax.set_ylabel(ylabel)
        annotate_bars(ax, bars)
        ax.set_ylim(0, max(values) * 1.18 if max(values) else 1)

    ax.set_title(title, fontsize=15, pad=14, weight="bold")
    ax.grid(axis="x" if horizontal else "y", color="#e3e7ee", linewidth=0.8)
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    fig.patch.set_facecolor("white")
    fig.tight_layout()
    fig.savefig(output_path, dpi=160, bbox_inches="tight")
    plt.close(fig)


def plot_status_distribution(results, output_path):
    labels, values = ordered_counts(
        results,
        lambda item: item.get("status", "unknown"),
        STATUS_ORDER,
    )
    save_bar_chart(
        labels,
        values,
        "RDP Status Distribution",
        "Status",
        "Number of hosts",
        output_path,
    )


def plot_risk_distribution(results, output_path):
    labels, values = ordered_counts(
        results,
        lambda item: item.get("risk", {}).get("level", "unknown"),
        RISK_ORDER,
    )
    save_bar_chart(
        labels,
        values,
        "Risk Level Distribution",
        "Risk level",
        "Number of hosts",
        output_path,
    )


def plot_policy_distribution(results, output_path):
    labels, values = ordered_counts(
        results,
        lambda item: item.get("policy", {}).get("status", "unknown"),
        POLICY_ORDER,
    )
    save_bar_chart(
        labels,
        values,
        "Policy Compliance Distribution",
        "Policy status",
        "Number of hosts",
        output_path,
    )


def plot_risk_by_host(results, output_path):
    sorted_results = sorted(
        results,
        key=lambda item: item.get("risk", {}).get("score", 0),
        reverse=True,
    )
    labels = [f"{item.get('host')}:{item.get('port')}" for item in sorted_results]
    values = [item.get("risk", {}).get("score", 0) for item in sorted_results]

    save_bar_chart(
        labels,
        values,
        "Risk Score by Host",
        "Risk score",
        "Host",
        output_path,
        horizontal=True,
    )


def plot_response_time(results, output_path):
    filtered = sorted(
        [item for item in results if item.get("response_time_ms") is not None],
        key=lambda item: item.get("response_time_ms", 0),
        reverse=True,
    )
    labels = [f"{item.get('host')}:{item.get('port')}" for item in filtered]
    values = [item.get("response_time_ms", 0) for item in filtered]

    save_bar_chart(
        labels,
        values,
        "Response Time by Host",
        "Response time (ms)",
        "Host",
        output_path,
        horizontal=True,
    )


def main():
    parser = argparse.ArgumentParser(description="Generate plots from RDP audit results")
    parser.add_argument("input", help="Input JSON file")
    parser.add_argument("--out-dir", default="reports/plots", help="Output directory")

    args = parser.parse_args()

    results = load_json(args.input)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    plot_status_distribution(results, out_dir / "rdp_status.png")
    plot_risk_distribution(results, out_dir / "risk_distribution.png")
    plot_policy_distribution(results, out_dir / "policy_status.png")
    plot_risk_by_host(results, out_dir / "risk_by_host.png")
    plot_response_time(results, out_dir / "response_time.png")

    print(f"Plots generated in {out_dir}")


if __name__ == "__main__":
    main()
