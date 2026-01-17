# modules/report.py
# Drakben Report Modülü - İleri Seviye Raporlama

import json
import datetime
from modules import ai_bridge

# -------------------------
# JSON Rapor
# -------------------------
def generate_json_report(recon_result, exploit_result, payload_result):
    print("[Report] JSON rapor oluşturuluyor...")
    report = {
        "timestamp": str(datetime.datetime.utcnow()),
        "recon": recon_result,
        "exploit": exploit_result,
        "payload": payload_result
    }
    return json.dumps(report, indent=4, ensure_ascii=False)

# -------------------------
# Markdown Rapor
# -------------------------
def generate_markdown_report(recon_result, exploit_result, payload_result):
    print("[Report] Markdown rapor oluşturuluyor...")
    md = f"# Drakben Güvenlik Raporu\n\n"
    md += f"**Tarih:** {datetime.datetime.utcnow()}\n\n"

    md += "## Recon Çıktısı\n"
    md += f"- Hedef: {recon_result.get('target')}\n"
    md += f"- Başlık: {recon_result.get('title')}\n"
    md += f"- Açıklama: {recon_result.get('description')}\n"
    md += f"- CMS: {recon_result.get('cms')}\n"
    md += f"- Formlar: {len(recon_result.get('forms', []))}\n\n"

    md += "## Exploit Çıktısı\n"
    if isinstance(exploit_result, dict):
        md += f"- Tür: {exploit_result.get('type')}\n"
        md += f"- Sonuç: {exploit_result}\n\n"
    else:
        md += f"- Exploit sonuçları: {exploit_result}\n\n"

    md += "## Payload Çıktısı\n"
    if isinstance(payload_result, dict):
        md += f"- Tür: {payload_result.get('type')}\n"
        md += f"- Sonuç: {payload_result}\n\n"
    else:
        md += f"- Payload sonuçları: {payload_result}\n\n"

    return md

# -------------------------
# AI Destekli Özet
# -------------------------
async def generate_ai_summary(recon_result, exploit_result, payload_result):
    print("[Report] AI özetleme çalışıyor...")
    combined = {
        "recon": recon_result,
        "exploit": exploit_result,
        "payload": payload_result
    }
    summary = await ai_bridge.analyze_report_output(combined)
    return summary
