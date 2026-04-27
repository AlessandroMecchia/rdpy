def generate_recommendations(result: dict, policy: dict | None = None) -> list[dict]:
    policy = policy or {}
    recommendations = []

    host = result.get("host")
    reachable = result.get("tcp_reachable")
    rdp_detected = result.get("rdp_detected")
    approved_hosts = set(policy.get("approved_rdp_hosts", []))
    allow_unknown_hosts = policy.get("allow_unknown_hosts", True)
    require_nla = policy.get("require_nla", False)
    require_tls = policy.get("require_tls", False)
    host_is_approved = host in approved_hosts

    if reachable and rdp_detected and not host_is_approved and not allow_unknown_hosts:
        recommendations.append({
            "priority": "high",
            "finding": "RDP is reachable on a non-approved host",
            "recommendation": "Disable RDP on this host or add it to the approved inventory after review.",
        })
    elif reachable and rdp_detected and host_is_approved:
        recommendations.append({
            "priority": "low",
            "finding": "Approved RDP service is reachable",
            "recommendation": "Keep access restricted to trusted networks, VPN, or a remote access gateway.",
        })
    elif reachable and rdp_detected:
        recommendations.append({
            "priority": "medium",
            "finding": "RDP service is reachable on an unlisted host",
            "recommendation": "Confirm whether this host should expose RDP and document the decision.",
        })
    elif reachable:
        recommendations.append({
            "priority": "medium",
            "finding": "TCP port is reachable, but RDP was not confirmed",
            "recommendation": "Verify the service listening on this port and close it if it is not required.",
        })

    nla = result.get("nla_required")
    if nla is False:
        recommendations.append({
            "priority": "high" if require_nla else "medium",
            "finding": "NLA is not required",
            "recommendation": "Enable Network Level Authentication where supported.",
        })
    elif nla in ("unknown", None) and reachable:
        recommendations.append({
            "priority": "medium" if require_nla else "low",
            "finding": "NLA status is unknown",
            "recommendation": "Verify NLA manually or with a deeper authenticated configuration check.",
        })

    tls = result.get("tls_supported")
    if tls is False:
        recommendations.append({
            "priority": "high" if require_tls else "medium",
            "finding": "TLS support was not detected",
            "recommendation": "Enable TLS for RDP and disable legacy security modes where possible.",
        })
    elif tls in ("unknown", None) and reachable:
        recommendations.append({
            "priority": "medium" if require_tls else "low",
            "finding": "TLS status is unknown",
            "recommendation": "Verify TLS support manually or with a deeper protocol check.",
        })

    policy_result = result.get("policy", {})
    for violation in policy_result.get("violations", []):
        if "Risk score" in violation:
            recommendations.append({
                "priority": "medium",
                "finding": violation,
                "recommendation": "Review the risk drivers and adjust exposure, TLS, NLA, or approval status.",
            })

    if not recommendations:
        recommendations.append({
            "priority": "low",
            "finding": "No major issue detected",
            "recommendation": "Continue monitoring RDP exposure and compare future scans against a baseline.",
        })

    return recommendations
