# modules/ai_bridge.py
# Drakben AI Bridge Modülü - İleri Seviye Analiz ve Öneri Motoru

import asyncio

# -------------------------
# Recon Analizi
# -------------------------
async def analyze_recon_output(recon_result):
    """
    Recon çıktısını AI ile analiz eder.
    Örnek: Hangi güvenlik testleri yapılmalı?
    """
    try:
        # Burada gerçek AI entegrasyonu olabilir (LLM API çağrısı vs.)
        # Şimdilik basit bir örnek JSON döndürüyoruz.
        advice = {
            "recommended_tests": []
        }

        if recon_result.get("cms") == "WordPress":
            advice["recommended_tests"].append("WordPress plugin enumeration")
            advice["recommended_tests"].append("XML-RPC brute force")

        if recon_result.get("forms"):
            advice["recommended_tests"].append("SQL Injection")
            advice["recommended_tests"].append("XSS")

        if recon_result.get("dns_records", {}).get("MX"):
            advice["recommended_tests"].append("Email spoofing test")

        return advice
    except Exception as e:
        return {"error": str(e)}

# -------------------------
# Exploit Analizi
# -------------------------
async def analyze_exploit_output(exploit_result):
    """
    Exploit çıktısını AI ile analiz eder.
    Örnek: Hangi payload denenmeli?
    """
    try:
        advice = {
            "next_payloads": []
        }

        if exploit_result.get("type") == "SQLi" and "vulnerable" in exploit_result.get("stdout", "").lower():
            advice["next_payloads"].append("SQLi data extraction")
            advice["next_payloads"].append("Privilege escalation via SQLi")

        if exploit_result.get("type") == "XSS" and exploit_result.get("vulnerable"):
            advice["next_payloads"].append("Session hijacking via XSS")
            advice["next_payloads"].append("Cookie theft")

        return advice
    except Exception as e:
        return {"error": str(e)}

# -------------------------
# Payload Analizi
# -------------------------
async def analyze_payload_output(payload_result):
    """
    Payload çıktısını AI ile analiz eder.
    Örnek: Shell sonrası hangi adımlar atılmalı?
    """
    try:
        advice = {
            "post_exploitation": []
        }

        if payload_result.get("type") == "ReverseShell" and payload_result.get("success"):
            advice["post_exploitation"].append("Privilege escalation")
            advice["post_exploitation"].append("Persistence mechanism installation")

        if payload_result.get("type") == "BindShell" and payload_result.get("success"):
            advice["post_exploitation"].append("Pivoting into internal network")

        return advice
    except Exception as e:
        return {"error": str(e)}

# -------------------------
# Report Analizi
# -------------------------
async def analyze_report_output(report_result):
    """
    Tüm zincir çıktısını AI ile özetler.
    """
    try:
        summary = {
            "overall_risk": "Medium",
            "key_findings": [],
            "recommended_actions": []
        }

        if report_result.get("recon", {}).get("cms") == "WordPress":
            summary["overall_risk"] = "High"
            summary["key_findings"].append("WordPress CMS detected")
            summary["recommended_actions"].append("Perform plugin vulnerability scan")

        if report_result.get("exploit", {}).get("type") == "SQLi":
            summary["key_findings"].append("SQL Injection attempt executed")
            summary["recommended_actions"].append("Harden database queries")

        if report_result.get("payload", {}).get("type") == "ReverseShell":
            summary["key_findings"].append("Reverse shell payload tested")
            summary["recommended_actions"].append("Monitor outbound connections")

        return summary
    except Exception as e:
        return {"error": str(e)}
