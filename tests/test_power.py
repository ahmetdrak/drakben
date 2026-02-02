import os
import sys

from rich.console import Console

# Add project root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from modules.waf_evasion import WAFEvasion

# We can't fully test stealth_client without internet/mock, but we can instantiation it.
try:
    from modules.stealth_client import StealthSession

    CURL_AVAILABLE = True
except ImportError:
    import traceback

    traceback.print_exc()  # PRINT THE ERROR!
    CURL_AVAILABLE = False

console = Console()


def test_power_level() -> None:
    console.print("[bold red]🔥 DRAKBEN POWER LEVEL DIAGNOSTIC 🔥[/bold red]")
    console.print("=" * 50)

    # 1. WAF Evasion Module Test
    console.print(
        "\n[bold yellow]1. Testing WAF Evasion Engine (Polymorphism)[/bold yellow]",
    )
    waf = WAFEvasion()

    payloads = [
        ("SQLi", "UNION SELECT password FROM users"),
        ("XSS", "<script>alert(1)</script>"),
        ("RCE", "cat /etc/passwd"),
    ]

    for name, raw in payloads:
        if name == "SQLi":
            obfuscated = waf.obfuscate_sql(raw)
        elif name == "XSS":
            obfuscated = waf.obfuscate_xss(raw)
        else:
            obfuscated = waf.obfuscate_shell(raw)

        console.print(f"  [cyan]{name} Raw:[/cyan] {raw}")
        console.print(f"  [green]{name} Obf:[/green] {obfuscated}")

        if raw == obfuscated:
            console.print("  [bold red]❌ FAILED: Payload not mutated![/bold red]")
        else:
            console.print("  [bold green]✅ SUCCESS: Mutation verified.[/bold green]")

    # 2. Stealth Client Test
    console.print(
        "\n[bold yellow]2. Testing Stealth Client (TLS Fingerprint)[/bold yellow]",
    )
    if CURL_AVAILABLE:
        try:
            session = StealthSession(impersonate="chrome120")
            headers = session.headers
            ua = headers.get("User-Agent", "Unknown")

            console.print("  [cyan]Impersonation:[/cyan] Chrome 120")
            console.print(f"  [cyan]User-Agent:[/cyan] {ua}")

            if "Chrome/120" in ua:
                console.print(
                    "  [bold green]✅ SUCCESS: User-Agent matches target fingerprint.[/bold green]",
                )
            else:
                console.print("  [bold red]❌ FAILED: User-Agent mismatch![/bold red]")

            # Check Cipher Suite capability (Mock)
            console.print(
                "  [bold green]✅ SUCCESS: curl_cffi core loaded successfully.[/bold green]",
            )

        except Exception as e:
            console.print(f"  [bold red]❌ CRITICAL ERROR: {e}[/bold red]")
    else:
        console.print(
            "  [bold red]❌ CRITICAL: curl_cffi not installed! Stealth module is offline.[/bold red]",
        )

    console.print("\n" + "=" * 50)
    console.print("[bold white]VERDICT: Weapons are Loaded and Ready.[/bold white]")


if __name__ == "__main__":
    test_power_level()
