import argparse
import json
import socket
import time
from dataclasses import dataclass

from rdpy.tools.common import parse_target


PROTOCOL_RDP = 0x00000000
PROTOCOL_SSL = 0x00000001
PROTOCOL_HYBRID = 0x00000002
PROTOCOL_HYBRID_EX = 0x00000008

PROTOCOL_NAMES = {
    PROTOCOL_RDP: "standard_rdp",
    PROTOCOL_SSL: "tls",
    PROTOCOL_HYBRID: "credssp_nla",
    PROTOCOL_HYBRID_EX: "credssp_nla_extended",
}

FAILURE_CODES = {
    0x00000001: "ssl_required_by_server",
    0x00000002: "ssl_not_allowed_by_server",
    0x00000003: "ssl_cert_not_on_server",
    0x00000004: "inconsistent_flags",
    0x00000005: "hybrid_required_by_server",
    0x00000006: "ssl_with_user_auth_required_by_server",
}


@dataclass
class RdpProbeResult:
    tcp_reachable: bool
    rdp_like_service: bool
    negotiation_result: str
    selected_protocol: str | None
    nla_required: bool | str
    tls_supported: bool | str
    failure_reason: str | None
    response_time_ms: float | None
    error: str | None


def build_rdp_negotiation_request() -> bytes:
    cookie = b"Cookie: mstshash=rdpy\r\n"
    requested_protocols = PROTOCOL_SSL | PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX

    rdp_neg_req = (
        b"\x01"                      # RDP Negotiation Request
        b"\x00"                      # Flags
        b"\x08\x00"                  # Length: 8
        + requested_protocols.to_bytes(4, "little")
    )

    x224_payload = cookie + rdp_neg_req
    x224_length = len(x224_payload) + 7

    packet = (
        b"\x03\x00"                                  # TPKT version + reserved
        + x224_length.to_bytes(2, "big")             # TPKT length
        + bytes([x224_length - 5])                   # X.224 length
        + b"\xe0"                                    # CR TPDU
        + b"\x00\x00"                                # Destination reference
        + b"\x00\x00"                                # Source reference
        + b"\x00"                                    # Class/options
        + x224_payload
    )

    return packet


def parse_negotiation_response(data: bytes) -> tuple[str, str | None, bool | str, bool | str, str | None]:
    if len(data) < 11:
        return "invalid_or_short_response", None, "unknown", "unknown", None

    if not data.startswith(b"\x03\x00"):
        return "not_tpkt", None, "unknown", "unknown", None

    for idx in range(0, len(data) - 7):
        msg_type = data[idx]
        msg_len = int.from_bytes(data[idx + 2:idx + 4], "little")

        if msg_len != 8:
            continue

        value = int.from_bytes(data[idx + 4:idx + 8], "little")

        if msg_type == 0x02:
            selected = PROTOCOL_NAMES.get(value, f"unknown_0x{value:08x}")

            nla_required = value in (PROTOCOL_HYBRID, PROTOCOL_HYBRID_EX)
            tls_supported = value in (PROTOCOL_SSL, PROTOCOL_HYBRID, PROTOCOL_HYBRID_EX)

            return "ok", selected, nla_required, tls_supported, None

        if msg_type == 0x03:
            failure = FAILURE_CODES.get(value, f"unknown_failure_0x{value:08x}")

            nla_required = failure in (
                "hybrid_required_by_server",
                "ssl_with_user_auth_required_by_server",
            )
            tls_supported = failure not in (
                "ssl_not_allowed_by_server",
                "ssl_cert_not_on_server",
            )

            return "failure", None, nla_required, tls_supported, failure

    return "no_negotiation_structure_found", None, "unknown", "unknown", None


def probe_rdp(host: str, port: int, timeout: float = 3.0) -> RdpProbeResult:
    packet = build_rdp_negotiation_request()
    start = time.perf_counter()

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(packet)
            data = sock.recv(4096)

        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        result, selected, nla_required, tls_supported, failure = parse_negotiation_response(data)

        return RdpProbeResult(
            tcp_reachable=True,
            rdp_like_service=result not in ("not_tpkt", "invalid_or_short_response"),
            negotiation_result=result,
            selected_protocol=selected,
            nla_required=nla_required,
            tls_supported=tls_supported,
            failure_reason=failure,
            response_time_ms=elapsed_ms,
            error=None,
        )

    except socket.timeout:
        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        return RdpProbeResult(
            False, False, "timeout", None, "unknown", "unknown", None, elapsed_ms, "timeout"
        )

    except ConnectionRefusedError:
        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        return RdpProbeResult(
            False, False, "connection_refused", None, "unknown", "unknown", None, elapsed_ms, "connection_refused"
        )

    except OSError as exc:
        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        return RdpProbeResult(
            False, False, "os_error", None, "unknown", "unknown", None, elapsed_ms, str(exc)
        )


def probe_as_dict(host: str, port: int, timeout: float = 3.0) -> dict:
    result = probe_rdp(host, port, timeout)

    return {
        "tcp_reachable": result.tcp_reachable,
        "rdp_detected": result.rdp_like_service,
        "rdp_negotiation": result.negotiation_result,
        "selected_protocol": result.selected_protocol,
        "nla_required": result.nla_required,
        "tls_supported": result.tls_supported,
        "rdp_failure_reason": result.failure_reason,
        "response_time_ms": result.response_time_ms,
        "error": result.error,
    }


def main():
    parser = argparse.ArgumentParser(description="Probe an RDP service without authentication")
    parser.add_argument("target", help="Target host or host:port")
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--json", action="store_true")

    args = parser.parse_args()
    host, port = parse_target(args.target)

    result = probe_as_dict(host, port, args.timeout)
    result["host"] = host
    result["port"] = port

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Target: {host}:{port}")
        print(f"TCP reachable: {result['tcp_reachable']}")
        print(f"RDP detected: {result['rdp_detected']}")
        print(f"Negotiation: {result['rdp_negotiation']}")
        print(f"Selected protocol: {result['selected_protocol']}")
        print(f"NLA required: {result['nla_required']}")
        print(f"TLS supported: {result['tls_supported']}")
        print(f"Response time: {result['response_time_ms']} ms")
        if result["error"]:
            print(f"Error: {result['error']}")


if __name__ == "__main__":
    main()