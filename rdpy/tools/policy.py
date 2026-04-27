import yaml


def load_policy(path: str | None) -> dict:
    if not path:
        return {}

    with open(path, "r", encoding="utf-8") as file:
        return yaml.safe_load(file) or {}


def evaluate_policy(result: dict, policy: dict) -> dict:
    violations = []
    warnings = []

    approved_hosts = set(policy.get("approved_rdp_hosts", []))
    allow_unknown_hosts = policy.get("allow_unknown_hosts", True)
    max_risk_score = policy.get("max_risk_score")
    require_nla = policy.get("require_nla", False)
    require_tls = policy.get("require_tls", False)
    treat_unknown_security_as_warning = policy.get("treat_unknown_security_as_warning", True)

    host = result.get("host")
    reachable = result.get("tcp_reachable", False)
    rdp_detected = result.get("rdp_detected", False)
    risk_score = result.get("risk", {}).get("score", 0)

    if reachable and rdp_detected and not allow_unknown_hosts and host not in approved_hosts:
        violations.append("RDP is reachable on a non-approved host")

    if max_risk_score is not None and risk_score > max_risk_score:
        violations.append(f"Risk score {risk_score} exceeds maximum allowed value {max_risk_score}")

    if require_nla and reachable and rdp_detected:
        nla = result.get("nla_required")
        if nla is not True:
            message = "NLA requirement could not be verified"
            if nla == "unknown" and treat_unknown_security_as_warning:
                warnings.append(message)
            else:
                violations.append(message)

    if require_tls and reachable and rdp_detected:
        tls = result.get("tls_supported")
        if tls is not True:
            message = "TLS requirement could not be verified"
            if tls == "unknown" and treat_unknown_security_as_warning:
                warnings.append(message)
            else:
                violations.append(message)

    if violations:
        status = "fail"
    elif warnings:
        status = "warning"
    else:
        status = "pass"

    return {
        "status": status,
        "violations": violations,
        "warnings": warnings,
    }
