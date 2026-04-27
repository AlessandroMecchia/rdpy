import argparse
from collections import Counter
from pathlib import Path

import matplotlib.pyplot as plt

from rdpy.tools.common import load_json


def save_bar_chart(labels, values, title, xlabel, ylabel, output_path, horizontal=False):
    plt.figure(figsize=(10, 5))

    if horizontal:
        plt.barh(labels, values)
    else:
        plt.bar(labels, values)

    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()


def plot_status_distribution(results, output_path):
    counts = Counter(item.get("status", "unknown") for item in results)
    save_bar_chart(
        list(counts.keys()),
        list(counts.values()),
        "RDP Status Distribution",
        "Status",
        "Number of hosts",
        output_path,
    )


def plot_risk_distribution(results, output_path):
    counts = Counter(item.get("risk", {}).get("level", "unknown") for item in results)
    save_bar_chart(
        list(counts.keys()),
        list(counts.values()),
        "Risk Level Distribution",
        "Risk level",
        "Number of hosts",
        output_path,
    )


def plot_policy_distribution(results, output_path):
    counts = Counter(item.get("policy", {}).get("status", "unknown") for item in results)
    save_bar_chart(
        list(counts.keys()),
        list(counts.values()),
        "Policy Compliance Distribution",
        "Policy status",
        "Number of hosts",
        output_path,
    )


def plot_risk_by_host(results, output_path):
    labels = [f"{item.get('host')}:{item.get('port')}" for item in results]
    values = [item.get("risk", {}).get("score", 0) for item in results]

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
    filtered = [item for item in results if item.get("response_time_ms") is not None]
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