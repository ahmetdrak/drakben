from rich.prompt import Prompt

def ask_approval(command, purpose, needs_root=False):
    print(f"\n🔧 Önerilen Komut:\n{command}")
    print(f"\n📌 Amaç:\n{purpose}")
    if needs_root:
        print("\n⚠️ Not: Root yetkisi gerektirir")

    choice = Prompt.ask(
        "\nOnaylıyor musun?",
        choices=["y", "e", "n"],
        default="n"
    )

    return choice
