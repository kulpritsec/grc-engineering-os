from .cli import app
from .version import __version__


def main() -> None:
    app()


__all__ = ["__version__", "app", "main"]
