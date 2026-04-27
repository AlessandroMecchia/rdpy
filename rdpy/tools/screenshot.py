from pathlib import Path


def capture_screenshot_placeholder(host: str, output_dir: str = "reports/screenshots") -> str | None:
    """
    Placeholder for future RDPY screenshot integration.

    The function intentionally does not capture screenshots yet.
    It provides a stable integration point for a future wrapper around
    rdpy-rdpscreenshot or another authorized screenshot backend.
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    return None