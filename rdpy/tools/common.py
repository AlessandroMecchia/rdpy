import json
from pathlib import Path


def parse_target(value: str) -> tuple[str, int]:
    value = value.strip()

    if not value:
        raise ValueError("Empty target value")

    if ":" in value:
        host, port = value.rsplit(":", 1)
        return host.strip(), int(port.strip())

    return value, 3389


def target_key(host: str, port: int) -> str:
    return f"{host}:{port}"


def load_targets(path: str) -> list[str]:
    targets = []

    with open(path, "r", encoding="utf-8") as file:
        for line in file:
            cleaned = line.strip()
            if cleaned and not cleaned.startswith("#"):
                targets.append(cleaned)

    return targets


def load_json(path: str):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def write_json(data, path: str) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)

    with open(output, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)


def ensure_dir(path: str) -> Path:
    output = Path(path)
    output.mkdir(parents=True, exist_ok=True)
    return output