
# drakben.py
# DRAKBEN Pentest Core - Dracula Edition

from core.executor import Executor
from core.chain_planner import ChainPlanner
from core.payload_intelligence import PayloadIntelligence
from llm.brain import DrakbenBrain

executor = Executor()
planner = ChainPlanner()
payload_ai = PayloadIntelligence()
brain = DrakbenBrain()

def show_menu():
    print("""
🩸 D R A K B E N
════════════════════════════════════════════════
🧠 Interactive Pentest Core

🔗  Zincir  : devam et           → zinciri kaldığı yerden sürdür
➕  Öneri   : more               → ek komut önerileri
🧹  Temizle : clear | /clear     → ekranı temizle
🚪  Çıkış   : exit | quit        → programdan çık

📜 Workflow: Recon → Exploit → Payload
💡 Yardım  : /help              → menüyü yeniden göster
════════════════════════════════════════════════
🩸 Drakben >
""")

# Sohbet cevap sözlüğü
responses = {
    "selam": "Merhaba Ahmet! Seni dinliyorum.",
    "merhaba": "Merhaba Ahmet! Hazır bekliyorum.",
    "hey": "Hey! Buradayım.",
    "naber": "İyiyim, sen nasılsın?",
    "nasılsın": "Gayet iyiyim, sen nasılsın?",
    "sa": "Aleyküm selam!"
}

def main():
    show_menu()
    while True:
        user_input = input("🩸 Drakben > ").strip()
        msg = user_input.lower()

        # Çıkış
        if msg in ["exit", "quit"]:
            print("🚪 Tabuta dönülüyor...")
            break

        # Temizle
        if msg in ["clear", "/clear", "/cls"]:
            print("\033c", end="")
            show_menu()
            continue

        # Yardım
        if msg == "/help":
            show_menu()
            continue

        # Zinciri devam ettir
        if msg == "devam et":
            chain = brain.continue_chain()
            if chain:
                outputs = executor.run_chain(chain)
                for o in outputs:
                    print(f"[{o['step']}] {o['command']} → {o['output']}")
            else:
                print("⚠ Hafızada zincir bulunamadı.")
            continue

        # Her giriş → Brain analizi
        analysis = brain.think(user_input)

        if analysis.get("chain"):
            print(f"🧠 Intent: {analysis.get('intent','bilinmiyor')}")
            print(f"📜 Zincir planlandı: {len(analysis['chain'])} adım")
            confirm = input("▶ Zincir çalıştırılsın mı? (y/N): ").lower()
            if confirm == "y":
                outputs = executor.run_chain(analysis["chain"])
                for o in outputs:
                    print(f"[{o['step']}] {o['command']} → {o['output']}")
            else:
                print("❌ Zincir iptal edildi.")
        else:
            # Sohbet fallback
            if msg in responses:
                print(f"🤖 {responses[msg]}")
            elif "reply" in analysis and analysis["reply"]:
                print(f"🤖 {analysis['reply']}")
            else:
                print("🤖 Bunu tam anlayamadım, biraz daha açık yazar mısın?")

if __name__ == "__main__":
    main()
