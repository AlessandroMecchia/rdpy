import argparse

from rdpy.tools.common import load_json, write_json


def index_by_target(results):
    return {
        f"{item.get('host')}:{item.get('port')}": item
        for item in results
    }


def classify_change(before, after):
    changes = []

    before_status = before.get("status")
    after_status = after.get("status")
    before_score = before.get("risk", {}).get("score", 0)
    after_score = after.get("risk", {}).get("score", 0)

    if before_status != after_status:
        if before_status != "open" and after_status == "open":
            severity = "high"
            message = "New RDP exposure detected"
        elif before_status == "open" and after_status != "open":
            severity = "info"
            message = "RDP service is no longer reachable"
        else:
            severity = "medium"
            message = "RDP status changed"

        changes.append({
            "field": "status",
            "before": before_status,
            "after": after_status,
            "severity": severity,
            "message": message,
        })

    if before_score != after_score:
        if after_score > before_score:
            severity = "medium"
            message = "Risk score increased"
        else:
            severity = "info"
            message = "Risk score decreased"

        changes.append({
            "field": "risk_score",
            "before": before_score,
            "after": after_score,
            "severity": severity,
            "message": message,
        })

    return changes


def compare_results(baseline, current):
    baseline_index = index_by_target(baseline)
    current_index = index_by_target(current)

    all_targets = sorted(set(baseline_index) | set(current_index))
    output = []

    for target in all_targets:
        before = baseline_index.get(target)
        after = current_index.get(target)

        if before and not after:
            output.append({
                "target": target,
                "change_type": "removed",
                "severity": "medium",
                "message": "Target was present in baseline but missing in current scan",
            })
            continue

        if after and not before:
            output.append({
                "target": target,
                "change_type": "added",
                "severity": "medium",
                "message": "Target is new in current scan",
            })
            continue

        for change in classify_change(before, after):
            change["target"] = target
            change["change_type"] = "modified"
            output.append(change)

    return output


def render_text(changes):
    if not changes:
        print("No changes detected.")
        return

    for change in changes:
        print(f"{change['target']}: {change['message']}")
        if "field" in change:
            print(f"  {change['field']}: {change['before']} -> {change['after']}")
        print(f"  severity: {change['severity']}")
        print()


def main():
    parser = argparse.ArgumentParser(description="Compare RDP audit baseline and current results")
    parser.add_argument("baseline")
    parser.add_argument("current")
    parser.add_argument("--out")

    args = parser.parse_args()

    baseline = load_json(args.baseline)
    current = load_json(args.current)
    changes = compare_results(baseline, current)

    if args.out:
        write_json(changes, args.out)
    else:
        render_text(changes)


if __name__ == "__main__":
    main()