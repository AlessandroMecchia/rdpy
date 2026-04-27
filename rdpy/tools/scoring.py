def calculate_score(result: dict, policy: dict | None = None) -> dict:
    policy = policy or {}

    score = 0
    reasons = []

    approved_hosts = set(policy.get("approved_rdp_hosts", []))
    allow_unknown_hosts = policy.get("allow_unknown_hosts", True)
    require_nla = policy.get("require_nla", False)
    require_tls = policy.get("require_tls", False)

    host = result.get("host")
    reachable = result.get("tcp_reachable", False)
    rdp_detected = result.get("rdp_detected", False)
    host_is_approved = host in approved_hosts

    if not reachable:
        reasons.append("RDP TCP port is not reachable")
        return {
            "score": 0,
            "level": "low",
            "reasons": reasons,
        }

    if not rdp_detected:
        score += 15
        reasons.append("TCP port is reachable, but RDP was not confirmed")
    elif host_is_approved:
        score += 25
        reasons.append("Approved RDP service is reachable")
    elif not allow_unknown_hosts:
        score += 55
        reasons.append("RDP is reachable on a non-approved host")
    else:
        score += 35
        reasons.append("RDP service is reachable on an unlisted host")

    nla = result.get("nla_required")
    tls = result.get("tls_supported")

    if nla is False:
        score += 25 if require_nla else 15
        reasons.append("NLA is not required")
    elif nla in ("unknown", None):
        score += 15 if require_nla else 8
        reasons.append("NLA status is unknown")

    if tls is False:
        score += 25 if require_tls else 15
        reasons.append("TLS support was not detected")
    elif tls in ("unknown", None):
        score += 15 if require_tls else 8
        reasons.append("TLS status is unknown")

    if result.get("auth_test") == "success":
        score += 20
        reasons.append("Authentication succeeded with test credentials")

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
