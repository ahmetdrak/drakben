# core/brain.py
# Drakben Brain - Ana Orkestra Modülü

import asyncio
import sys

from core import system_profile
from modules import recon, exploit, payload, report, memory, ai_bridge

async def main(target):
    print(f"[+] Hedef: {target}")

    # -------------------------
    # Local System Info
    # -------------------------
    info = system_profile.local_system_info()
    print("[System] Çalıştığım sistem bilgileri:", info)

    # Örnek shell komutu çıktıları
    print("[System] pwd çıktısı:", system_profile.run_shell_command("pwd"))
    print("[System] whoami çıktısı:", system_profile.run_shell_command("whoami"))
    print("[System] uname -a çıktısı:", system_profile.run_shell_command("uname -a"))

    # -------------------------
    # Recon
    # -------------------------
    print("[*] Recon başlatılıyor...")
    recon_result = await recon.passive_recon(target)
    memory.memory_instance.save_recon(recon_result)

    ai_recon_advice = await ai_bridge.analyze_recon_output(recon_result)
    print(f"[AI] Recon önerileri: {ai_recon_advice}")

    # -------------------------
    # Exploit
    # -------------------------
    print("[*] Exploit başlatılıyor...")
    exploit_result = exploit.run_sqlmap(target)
    memory.memory_instance.save_exploit(exploit_result)

    ai_exploit_advice = await ai_bridge.analyze_exploit_output(exploit_result)
    print(f"[AI] Exploit önerileri: {ai_exploit_advice}")

    # XSS ve LFI testleri
    xss_result = await exploit.test_xss(target)
    lfi_result = await exploit.test_lfi(target)
    print(f"[Exploit] XSS sonucu: {xss_result}")
    print(f"[Exploit] LFI sonucu: {lfi_result}")

    # -------------------------
    # Payload
    # -------------------------
    print("[*] Payload başlatılıyor...")
    payload_result = await payload.reverse_shell("127.0.0.1", 4444)
    memory.memory_instance.save_payload(payload_result)

    ai_payload_advice = await ai_bridge.analyze_payload_output(payload_result)
    print(f"[AI] Payload önerileri: {ai_payload_advice}")

    # -------------------------
    # System Profile (Target)
    # -------------------------
    print("[*] System Profile başlatılıyor...")
    sysprof_result = await system_profile.profile_target(
        target.replace("https://","").replace("http://","")
    )
    print(f"[SystemProfile] Çıktı: {sysprof_result}")

    # -------------------------
    # Report
    # -------------------------
    print("[*] Rapor oluşturuluyor...")
    json_report = report.generate_json_report(recon_result, exploit_result, payload_result)
    md_report = report.generate_markdown_report(recon_result, exploit_result, payload_result)
    memory.memory_instance.save_report(json_report)

    ai_summary = await report.generate_ai_summary(recon_result, exploit_result, payload_result)
    print(f"[AI] Genel Özet: {ai_summary}")

    print("\n=== JSON RAPOR ===")
    print(json_report)

    print("\n=== MARKDOWN RAPOR ===")
    print(md_report)

    print("\n=== SESSION SUMMARY ===")
    print(memory.memory_instance.get_session_summary())

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Kullanım: python -m core.brain <target_url>")
        sys.exit(1)

    target = sys.argv[1]
    asyncio.run(main(target))
