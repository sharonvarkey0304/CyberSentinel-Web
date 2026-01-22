import typer
from autopwn.orchestrator import run_scan

app = typer.Typer(add_completion=False)

@app.command()
def scan(
    target: str,
    email: str = typer.Option(None, "--email", help="Auth email (optional)"),
    password: str = typer.Option(None, "--password", help="Auth password (optional)"),
):
    run_scan(target, auth_email=email, auth_password=password)
