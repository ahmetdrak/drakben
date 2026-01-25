#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SonarQube Cloud Quality Gate Güncelleme Script'i
Security Hotspots Reviewed koşulunu kaldırır veya eşiğini düşürür.
"""

import os
import sys
import requests
from typing import Optional, Dict, Any

# Windows encoding fix
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# SonarQube Cloud API base URL
SONARCLOUD_API_BASE = "https://sonarcloud.io/api"

# Proje bilgileri
PROJECT_KEY = "ahmetdrak_drakben"
ORGANIZATION = "ahmetdrak"


def get_quality_gate_id(api_token: str, project_key: str, organization: str) -> Optional[str]:
    """Projenin kullandığı Quality Gate ID'sini alır."""
    url = f"{SONARCLOUD_API_BASE}/qualitygates/get_by_project"
    params = {"project": project_key, "organization": organization}
    headers = {"Authorization": f"Bearer {api_token}"}
    
    try:
        response = requests.get(url, params=params, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        quality_gate = data.get("qualityGate")
        if quality_gate:
            return quality_gate.get("id")
        return None
    except requests.exceptions.RequestException as e:
        print(f"[HATA] Quality Gate ID alinamadi: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"   Status Code: {e.response.status_code}")
            print(f"   Response: {e.response.text}")
        return None


def list_quality_gate_conditions(api_token: str, gate_id: str, organization: str) -> Optional[Dict[str, Any]]:
    """Quality Gate'in tüm koşullarını listeler."""
    url = f"{SONARCLOUD_API_BASE}/qualitygates/show"
    params = {"id": gate_id, "organization": organization}
    headers = {"Authorization": f"Bearer {api_token}"}
    
    try:
        response = requests.get(url, params=params, headers=headers, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"[HATA] Quality Gate kosullari alinamadi: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"   Response: {e.response.text}")
        return None


def find_security_hotspots_condition(gate_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Security Hotspots Reviewed koşulunu bulur."""
    conditions = gate_data.get("conditions", [])
    for condition in conditions:
        metric = condition.get("metric", "")
        if "security_hotspots_reviewed" in metric.lower():
            return condition
    return None


def remove_condition(api_token: str, gate_id: str, condition_id: str, organization: str) -> bool:
    """Quality Gate koşulunu kaldırır."""
    url = f"{SONARCLOUD_API_BASE}/qualitygates/delete_condition"
    params = {"id": condition_id, "organization": organization}
    headers = {"Authorization": f"Bearer {api_token}"}
    
    try:
        response = requests.post(url, params=params, headers=headers, timeout=10)
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException as e:
        print(f"❌ Koşul kaldırılamadı: {e}")
        if hasattr(e.response, 'text'):
            print(f"   Response: {e.response.text}")
        return False


def update_condition_threshold(
    api_token: str, 
    gate_id: str, 
    condition_id: str, 
    new_threshold: str,
    organization: str
) -> bool:
    """Quality Gate koşulunun eşiğini günceller."""
    url = f"{SONARCLOUD_API_BASE}/qualitygates/update_condition"
    params = {
        "id": condition_id,
        "error": new_threshold,  # Eşik değeri (örn: "0" veya "50")
        "organization": organization
    }
    headers = {"Authorization": f"Bearer {api_token}"}
    
    try:
        response = requests.post(url, params=params, headers=headers, timeout=10)
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException as e:
        print(f"[HATA] Kosul guncellenemedi: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"   Response: {e.response.text}")
        return False


def create_quality_gate(api_token: str, name: str, organization: str) -> Optional[str]:
    """Yeni bir Quality Gate oluşturur."""
    url = f"{SONARCLOUD_API_BASE}/qualitygates/create"
    params = {"name": name, "organization": organization}
    headers = {"Authorization": f"Bearer {api_token}"}
    
    try:
        response = requests.post(url, params=params, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        return data.get("id")
    except requests.exceptions.RequestException as e:
        print(f"[HATA] Quality Gate olusturulamadi: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"   Response: {e.response.text}")
        return None


def copy_conditions_except_security_hotspots(
    api_token: str, 
    source_gate_id: str, 
    target_gate_id: str, 
    organization: str
) -> bool:
    """Kaynak Quality Gate'in koşullarını hedefe kopyalar (Security Hotspots hariç)."""
    # Kaynak koşulları al
    source_data = list_quality_gate_conditions(api_token, source_gate_id, organization)
    if not source_data:
        return False
    
    conditions = source_data.get("conditions", [])
    
    # Her koşulu kopyala (Security Hotspots hariç)
    for condition in conditions:
        metric = condition.get("metric", "")
        if "security_hotspots_reviewed" in metric.lower():
            print(f"[ATLANDI] Security Hotspots kosulu kopyalanmadi: {metric}")
            continue
        
        # Yeni koşul oluştur
        url = f"{SONARCLOUD_API_BASE}/qualitygates/create_condition"
        params = {
            "gateId": target_gate_id,
            "metric": metric,
            "op": condition.get("op", "GT"),
            "organization": organization
        }
        
        # Eşik değerlerini ekle
        error = condition.get("error")
        warning = condition.get("warning")
        if error:
            params["error"] = error
        if warning:
            params["warning"] = warning
        
        headers = {"Authorization": f"Bearer {api_token}"}
        
        try:
            response = requests.post(url, params=params, headers=headers, timeout=10)
            response.raise_for_status()
            print(f"[KOPYALANDI] {metric}")
        except requests.exceptions.RequestException as e:
            print(f"[HATA] Kosul kopyalanamadi ({metric}): {e}")
            if hasattr(e, 'response') and e.response is not None:
                print(f"   Response: {e.response.text}")
    
    return True


def assign_quality_gate_to_project(
    api_token: str, 
    gate_id: str, 
    project_key: str, 
    organization: str
) -> bool:
    """Quality Gate'i projeye atar."""
    url = f"{SONARCLOUD_API_BASE}/qualitygates/select"
    params = {
        "gateId": gate_id,
        "projectKey": project_key,
        "organization": organization
    }
    headers = {"Authorization": f"Bearer {api_token}"}
    
    try:
        response = requests.post(url, params=params, headers=headers, timeout=10)
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException as e:
        print(f"[HATA] Quality Gate projeye atanamadi: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"   Response: {e.response.text}")
        return False


def main():
    """Ana fonksiyon."""
    print("SonarQube Cloud Quality Gate Guncelleme\n")
    
    # API token kontrolü
    api_token = os.getenv("SONAR_TOKEN") or os.getenv("SONARCLOUD_TOKEN")
    if not api_token:
        print("[HATA] SonarQube API token bulunamadi!")
        print("\nToken'i su sekilde ayarlayin:")
        print("   Windows PowerShell: $env:SONAR_TOKEN='your-token-here'")
        print("   Linux/Mac: export SONAR_TOKEN='your-token-here'")
        print("\nToken'i almak icin:")
        print("   1. https://sonarcloud.io/ -> My Account -> Security")
        print("   2. 'Generate Token' butonuna tiklayin")
        print("   3. Token'i kopyalayin ve yukaridaki komutu calistirin")
        sys.exit(1)
    
    # Quality Gate ID'sini al
    print(f"[INFO] Proje: {PROJECT_KEY}")
    print("[INFO] Quality Gate ID'si aliniyor...")
    gate_id = get_quality_gate_id(api_token, PROJECT_KEY, ORGANIZATION)
    
    if not gate_id:
        print("\n[UYARI] Quality Gate ID bulunamadi. Proje ayarlarini kontrol edin.")
        sys.exit(1)
    
    print(f"[OK] Quality Gate ID: {gate_id}\n")
    
    # Koşulları listele
    print("[INFO] Quality Gate kosullari aliniyor...")
    gate_data = list_quality_gate_conditions(api_token, gate_id, ORGANIZATION)
    
    if not gate_data:
        print("[HATA] Kosullar alinamadi.")
        sys.exit(1)
    
    # Quality Gate'in built-in olup olmadığını kontrol et
    gate_name = gate_data.get("name", "")
    is_builtin = gate_data.get("isBuiltIn", False)
    
    # Security Hotspots Reviewed koşulunu bul
    condition = find_security_hotspots_condition(gate_data)
    
    if not condition:
        print("[OK] 'Security Hotspots Reviewed' kosulu bulunamadi.")
        print("     Quality Gate'de zaten bu kosul yok veya farkli bir isimle tanimli.")
        sys.exit(0)
    
    condition_id = condition.get("id")
    metric = condition.get("metric", "")
    current_threshold = condition.get("error", "N/A")
    
    print(f"[BULUNDU] Kosul:")
    print(f"   Metric: {metric}")
    print(f"   Mevcut esik: {current_threshold}")
    print(f"   Quality Gate: {gate_name} (Built-in: {is_builtin})\n")
    
    # Built-in Quality Gate ise yeni bir tane oluştur
    if is_builtin:
        print("[UYARI] Built-in Quality Gate degistirilemez!")
        print("[COZUM] Yeni bir ozel Quality Gate olusturulup projeye atanacak.\n")
        
        new_gate_name = f"{gate_name} (Custom - No Security Hotspots)"
        print(f"[ISLEM] Yeni Quality Gate olusturuluyor: {new_gate_name}")
        new_gate_id = create_quality_gate(api_token, new_gate_name, ORGANIZATION)
        
        if not new_gate_id:
            print("[HATA] Yeni Quality Gate olusturulamadi.")
            sys.exit(1)
        
        print(f"[OK] Yeni Quality Gate olusturuldu (ID: {new_gate_id})\n")
        
        print("[ISLEM] Kosullar kopyalaniyor (Security Hotspots haric)...")
        if not copy_conditions_except_security_hotspots(api_token, gate_id, new_gate_id, ORGANIZATION):
            print("[HATA] Kosullar kopyalanamadi.")
            sys.exit(1)
        
        print("\n[ISLEM] Yeni Quality Gate projeye ataniyor...")
        if not assign_quality_gate_to_project(api_token, new_gate_id, PROJECT_KEY, ORGANIZATION):
            print("[HATA] Quality Gate projeye atanamadi.")
            sys.exit(1)
        
        print("[OK] Yeni Quality Gate basariyla projeye atandi!")
        print("\n[SONUC] Proje artik 'Security Hotspots Reviewed' kosulu olmayan yeni Quality Gate'i kullaniyor.")
    
    else:
        # Özel Quality Gate ise direkt değiştir
        auto_mode = os.getenv("AUTO_MODE", "").lower() == "true"
        
        if auto_mode:
            choice = "1"  # Otomatik olarak koşulu kaldır
            print("[AUTO] Otomatik mod: Kosul kaldiriliyor...")
        else:
            print("Ne yapmak istersiniz?")
            print("  1. Kosulu tamamen kaldir (onerilen)")
            print("  2. Esigi dusur (orn: 0% veya 50%)")
            choice = input("\nSeciminiz (1 veya 2): ").strip()
        
        if choice == "1":
            print("\n[ISLEM] Kosul kaldiriliyor...")
            if remove_condition(api_token, gate_id, condition_id, ORGANIZATION):
                print("[OK] Kosul basariyla kaldirildi!")
                print("\n[SONUC] Quality Gate artik 'Security Hotspots Reviewed' kosulunu kontrol etmeyecek.")
            else:
                print("[HATA] Kosul kaldirilamadi.")
                sys.exit(1)
        
        elif choice == "2":
            new_threshold = input("Yeni esik degeri (orn: 0, 50, 80): ").strip()
            if not new_threshold.isdigit():
                print("[HATA] Gecersiz esik degeri. Sayi olmali.")
                sys.exit(1)
            
            print(f"\n[ISLEM] Esik {current_threshold} -> {new_threshold} olarak guncelleniyor...")
            if update_condition_threshold(api_token, gate_id, condition_id, new_threshold, ORGANIZATION):
                print(f"[OK] Esik basariyla {new_threshold}% olarak guncellendi!")
            else:
                print("[HATA] Esik guncellenemedi.")
                sys.exit(1)
        
        else:
            print("[HATA] Gecersiz secim.")
            sys.exit(1)
    
    print("\n[TAMAMLANDI] Islem basariyla tamamlandi!")
    print(f"   Proje: https://sonarcloud.io/project/overview?id={PROJECT_KEY}")


if __name__ == "__main__":
    main()
