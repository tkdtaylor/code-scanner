"""A small, benign module — no malicious patterns, no risky calls."""

import click
import requests


@click.command()
@click.argument("url")
def fetch(url: str) -> None:
    """Fetch a URL and print its status code."""
    resp = requests.get(url, timeout=10)
    click.echo(f"{url} -> {resp.status_code}")


if __name__ == "__main__":
    fetch()
