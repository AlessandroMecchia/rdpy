def calculate_score(result: dict, policy: dict | None = None) -> dict:
    policy = policy or {}

    score = 0
    reasons = []

    approved_hosts = set(policy.get("approved_rdp_hosts", []))
    host = result.get("host")
    reachable = result.get("tcp_reachable", False)
    rdp_detected = result.get("rdp_detected", False)

    if reachable:
        score += 35
        reasons.append("RDP TCP port is reachable")
    else:
        reasons.append("RDP TCP port is not reachable")

    if rdp_detected:
        score += 10
        reasons.append("RDP-like negotiation response detected")

    if reachable and host not in approved_hosts:
        score += 25
        reasons.append("RDP is reachable on a non-approved host")

    nla = result.get("nla_required")
    tls = result.get("tls_supported")

    if reachable and nla in (False, "unknown", None):
        score += 15
        reasons.append("NLA status is false or unknown")

    if reachable and tls in (False, "unknown", None):
        score += 10
        reasons.append("TLS status is false or unknown")

    if result.get("auth_test") == "success":
        score += 10
        reasons.append("Authentication succeeded with test credentials")

    if host in approved_hosts:
        score -= 15
        reasons.append("Host is approved for RDP")

    score = max(0, min(score, 100))

    if score <= 30:
        level = "low"
    elif score <= 60:
        level = "medium"
    else:
        level = "high"

    return {
        "score": score,
        "level": level,
        "reasons": reasons,
    }