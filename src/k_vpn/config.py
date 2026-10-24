"""XDG locations and explicit user preferences; imports never create files."""

import json
import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    attempts: int = 5
    tuning: str = "native"
    strict_discovery: bool = False


def _xdg(variable: str, fallback: str) -> Path:
    value = os.environ.get(variable)
    base = (
        Path(value) if value and Path(value).is_absolute() else Path.home() / fallback
    )
    if base.resolve() == Path.home().resolve():
        base = Path.home() / fallback
    return base / "k-vpn"


def config_file() -> Path:
    return _xdg("XDG_CONFIG_HOME", ".config") / "config.json"


def cache_file() -> Path:
    return _xdg("XDG_CACHE_HOME", ".cache") / "measurements.json"


def load() -> Settings:
    path = config_file()
    if not path.exists():
        return Settings()
    payload = json.loads(path.read_text())
    # Earlier releases generated these two automatic-measurement preferences.
    # Accept them when reading old files, but never let them trigger traffic.
    legacy = {"bench", "min_speed"}
    if not isinstance(payload, dict) or set(payload) - (
        set(asdict(Settings())) | legacy
    ):
        raise ValueError(f"Unknown settings or invalid object in {path}")
    settings = Settings(
        **{key: value for key, value in payload.items() if key not in legacy}
    )
    if type(settings.attempts) is not int or settings.attempts < 1:
        raise ValueError("attempts must be a positive integer")
    if settings.tuning not in ("native", "balanced"):
        raise ValueError("tuning must be native or balanced")
    if type(settings.strict_discovery) is not bool:
        raise ValueError("strict_discovery must be a boolean")
    return settings


def initialize() -> None:
    """Create the requested XDG configuration once; never overwrite preferences."""
    path = config_file()
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return
    with os.fdopen(descriptor, "w") as stream:
        json.dump(asdict(Settings()), stream, indent=2)
        stream.write("\n")


@contextmanager
def session_directory() -> Iterator[str]:
    """Private ephemeral files only: XDG_RUNTIME_DIR, otherwise Linux /tmp."""
    value = os.environ.get("XDG_RUNTIME_DIR", "")
    parent = Path(value) if value else Path("/tmp")
    if (
        not parent.is_absolute()
        or not parent.is_dir()
        or parent.resolve() == Path.home().resolve()
    ):
        parent = Path("/tmp")
    with tempfile.TemporaryDirectory(prefix="k-vpn-", dir=parent) as directory:
        yield directory
