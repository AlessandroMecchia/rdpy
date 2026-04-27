import argparse
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from rdpy.tools.common import load_targets, parse_target, write_json
from rdpy.tools.policy import load_policy, evaluate_policy
from rdpy.tools.rdpinfo import probe_as_dict
from rdpy.tools.recommendations import generate_recommendations
from rdpy.tools.scoring import calculate_score
from rdpy.tools.screenshot import capture_screenshot_placeholder


def audit_target(target: str, timeout: float, policy: dict, screenshot: bool = False) -> dict:
    host, port = parse_target(target)

    probe = probe_as_dict(host, port, timeout)

    result = {
        "host": host,
        "port": port,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "tcp_reachable": probe["tcp_reachable"],
        "status": "open" if probe["tcp_reachable"] else "closed_or_unreachable",
        "response_time_ms": probe["response_time_ms"],
        "rdp_detected": probe["rdp_detected"],
        "rdp_negotiation": probe["rdp_negotiation"],
        "selected_protocol": probe["selected_protocol"],
        "tls_supported": probe["tls_supported"],
        "nla_required": probe["nla_required"],
        "rdp_failure_reason": probe["rdp_failure_reason"],
        "auth_test": "not_attempted",
        "screenshot": None,
        "error": probe["error"],
    }

    if screenshot and result["tcp_reachable"]:
        result["screenshot"] = capture_screenshot_placeholder(host)

    result["risk"] = calculate_score(result, policy)
    result["policy"] = evaluate_policy(result, policy)
    result["recommendations"] = generate_recommendations(result, policy)

    return result


def render_text(results: list[dict]) -> None:
    for item in results:
        print(f"Target: {item['host']}:{item['port']}")
        print(f"Status: {item['status']}")
        print(f"TCP reachable: {item['tcp_reachable']}")
        print(f"RDP detected: {item['rdp_detected']}")
        print(f"RDP negotiation: {item['rdp_negotiation']}")
        print(f"Selected protocol: {item['selected_protocol']}")
        print(f"NLA required: {item['nla_required']}")
        print(f"TLS supported: {item['tls_supported']}")
        print(f"Response time: {item['response_time_ms']} ms")
        print(f"Risk: {item['risk']['level']} ({item['risk']['score']})")
        print(f"Policy: {item['policy']['status']}")

        if item["error"]:
            print(f"Error: {item['error']}")

        print("Recommendations:")
        for rec in item.get("recommendations", []):
            print(f"- [{rec['priority']}] {rec['recommendation']}")

        print()


def main():
    parser = argparse.ArgumentParser(description="RDP defensive audit tool for authorized environments")
    parser.add_argument("target", nargs="?", help="Target host or host:port")
    parser.add_argument("--targets", help="File containing targets")
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--policy", help="YAML policy file")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--screenshot", action="store_true", help="Enable optional screenshot integration hook")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--out", help="Write output to file")

    args = parser.parse_args()
    policy = load_policy(args.policy)

    if args.targets:
        targets = load_targets(args.targets)
    elif args.target:
        targets = [args.target]
    else:
        parser.error("Provide a target or --targets file")

    results = []

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(audit_target, target, args.timeout, policy, args.screenshot): target
            for target in targets
        }

        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda item: (item["host"], item["port"]))

    if args.json:
        if args.out:
            write_json(results, args.out)
        else:
            print(json.dumps(results, indent=2))
    else:
        render_text(results)


if __name__ == "__main__":
    main()
