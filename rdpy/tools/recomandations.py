def generate_recommendations(result: dict) -> list[dict]:
    recommendations = []

    if result.get("tcp_reachable"):
        recommendations.append({
            "priority": "medium",
            "finding": "RDP service is reachable",
            "recommendation": "Restrict RDP access to trusted networks, VPN, or a remote access gateway.",
        })

    if result.get("rdp_detected"):
        recommendations.append({
            "priority": "low",
            "finding": "RDP-like service detected",
            "recommendation": "Maintain an approved inventory of systems allowed to expose RDP.",
        })

    if result.get("nla_required") in (False, "unknown", None) and result.get("tcp_reachable"):
        recommendations.append({
            "priority": "medium",
            "finding": "NLA status is false or unknown",
            "recommendation": "Verify that Network Level Authentication is enabled where supported.",
        })

    if result.get("tls_supported") in (False, "unknown", None) and result.get("tcp_reachable"):
        recommendations.append({
            "priority": "medium",
            "finding": "TLS status is false or unknown",
            "recommendation": "Verify that TLS is supported and correctly configured for RDP.",
        })

    policy = result.get("policy", {})

    for violation in policy.get("violations", []):
        if "non-approved host" in violation:
            recommendations.append({
                "priority": "high",
                "finding": violation,
                "recommendation": "Disable RDP on this host or formally approve it after review.",
            })

        if "Risk score" in violation:
            recommendations.append({
                "priority": "medium",
                "finding": violation,
                "recommendation": "Review configuration, reduce exposure, and verify access restrictions.",
            })

    if not recommendations:
        recommendations.append({
            "priority": "low",
            "finding": "No major issue detected",
            "recommendation": "Continue monitoring RDP exposure and compare future scans against a baseline.",
        })

    return recommendations