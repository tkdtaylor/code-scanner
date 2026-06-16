"""A small, benign module — no malicious patterns, no risky calls."""

import click


@click.command()
@click.argument("name")
def greet(name: str) -> None:
    """Print a greeting."""
    click.echo(f"Hello, {name}!")


if __name__ == "__main__":
    greet()
