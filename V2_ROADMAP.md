# ⚔️ "VILLAGER KILLER" - Drakben V2.0 Roadmap

Bu yol haritası, Drakben'i sadece bir "araç" olmaktan çıkarıp, **Villager** ve benzeri rakipleri her kulvarda (Zeka, Gizlilik, Envanter, Sızma) geride bırakacak bir "Advanced Persistent Threat (APT)" ajanına dönüştürmek için tasarlanmıştır.

> **Hedef:** Villager'ın "Otomasyonunu" korumak, ancak onun sahip olmadığı "Sürekli Öğrenen Zeka (Self-Refining)" ve "Askeri Düzeyde Gizlilik (Stealth)" yeteneklerini eklemek. Sadece "daha iyi" değil, "algılanamaz" olmak.

---

## 🏗️ Faz 1: GHOST PROTOCOL (Gizlilik ve Görünmezlik)
*Mevcut Durum: %10 (Temel Log Temizleme)*
*Hedef: %100 (EDR/AV Atlatma ve Dijital İz Bırakmama)*

- [ ] **Polimorfik Motor (The Shapeshifter):**
    - [ ] `AST Transformer`: `core/coder.py` içine, üretilen Python kodlarının Sözdizim Ağacını (AST) her seferinde yeniden yazan bir motor. Değişken isimleri, döngü yapıları ve ölü kod (dead code) ekleyerek imza tabanlı taramaları atlatır.
    - [ ] **PyArmor Entegrasyonu:** Kritik modüllerin çalışma zamanında (runtime) şifresinin çözülmesini sağlayan yapı.
    - [ ] **Obfuscation Pipeline:** Kodun okunabilirliğini yok eden ve statik analizi imkansız kılan otomatik zincir.

- [ ] **Memory-Only Execution (Fileless):**
    - [ ] Diske asla `.py` veya `.exe` yazma.
    - [ ] Linux: `memfd_create` syscall kullanımı ile RAM üzerinden çalıştırma.
    - [ ] Windows: .NET Assembly Reflective Loading veya PowerShell `IEX` üzerinden bellek içi çalıştırma.

- [ ] **Efemeral Mod (Anti-Forensics):**
    - [ ] Görev bitince `Secure Delete` (DoD standardı Overwrite) ile tüm kalıntıları silme.
    - [ ] Timestomping (Dosya oluşturma tarihlerini kernel32.dll gibi sistem dosyalarıyla eşleme).
    - [ ] RAM temizliği (Hassas verilerin bellekten güvenli silinmesi).

---

## 🔫 Faz 2: WEAPON FOUNDRY (Saldırı Envanteri)
*Mevcut Durum: %40 (Temel Recon/Exploit)*
*Hedef: %100 (Kurumsal Saldırı Seti)*

- [ ] **Dinamik Payload Üreticisi:**
    - [ ] Villager'ın yaptığı "Custom Payload" işini geçmek için.
    - [ ] MSFvenom wrapper yerine, saf Python/C ile shellcode üreten ve bunu XOR/AES ve RC4 ile şifreleyen yapı.
    - [ ] **Formatlar:** exe, elf, dll, hta, vbs, macro, powershell.

- [ ] **C2 (Komuta Kontrol) Mimarisi:**
    - [ ] Şu anki "Reverse Shell" mantığından, "Encrypted C2 Channel" mantığına geçiş.
    - [ ] HTTP/S (Domain Fronting), DNS Tunneling üzerinden haberleşen beacon'lar.
    - [ ] Heartbeat mekanizması (Ajanın hayatta olduğunu ve durumunu bildirmesi).
    - [ ] Jitter (Haberleşme aralıklarını rastgeleleştirerek trafik analizini atlatma).

---

## 🧠 Faz 3: HIVE MIND (Kurumsal Zeka & Pivot)
*Mevcut Durum: %70 (Tekil Hedef Analizi)*
*Hedef: %100 (Ağ Topolojisi Analizi ve Yayılma)*

- [ ] **Active Directory (AD) Hakimiyeti:**
    - [ ] **Kan İzi Modülü (BloodHound Entegrasyonu):** Domain Admin'e giden en kısa yolu hesaplayan grafik algoritması entegrasyonu.
    - [ ] Kerberoasting, AS-REP Roasting, DCSync saldırılarının otonomlaştırılması.
    - [ ] Impacket kütüphanesinin (psexec, wmiexec, smbexec, secretsdump) native entegrasyonu.

- [ ] **Lateral Movement (Yanal Hareket):**
    - [ ] "Bu makinede işim bitti, komşusuna nasıl sıçrarım?" mantığı.
    - [ ] Pass-the-Hash ve Pass-the-Ticket otomasyonu.
    - [ ] SSH Key Harvesting (otomatik key, known_hosts toplama ve deneme).
    - [ ] Token Impersonation (Yetkili kullanıcı tokenlarını çalma).

---

## 🔌 Faz 4: UNIVERSAL ADAPTER (MCP & Genişleme)
*Mevcut Durum: %20 (Plugin Sistemi)*
*Hedef: %100 (Sınırsız Entegrasyon ve Kendi Kendine Kurulum)*

- [ ] **Model Context Protocol (MCP) İstemcisi:**
    - [ ] Drakben'i Claude, OpenAI veya yerel LLM'lerin "Tools" yeteneğiyle standart bir protokolle konuşturma.
    - [ ] Bu sayede Drakben, dış dünyadaki herhangi bir MCP uyumlu sunucudan (örn: GitHub, Shodan, Jira) veri çekebilir.
    - [ ] LLM'in ajanı bir "araç" olarak değil, bir "ortak" olarak görmesini sağlayan protokol.

- [ ] **Otomatik Araç Kurulumu (Dependency Resolver):**
    - [ ] "Nmap yok mu? İndir ve kur." "Go yüklü değil mi? Kur."
    - [ ] Araçları `tools/` klasörüne izole bir şekilde kuran paket yöneticisi.
    - [ ] Sistem bağımlılıklarını (apt, pacman, yum) otomatik yönetme.

---

## 📊 Kıyaslama Tablosu (Hedeflenen)

| Özellik | Villager | DRAKBEN V2.0 (Hedef) |
| :--- | :---: | :---: |
| **Zeka** | LLM Wrapper (Çevirmen) | **Self-Refining (Otonom Karar & Hata Düzeltme)** |
| **Gizlilik** | Standart | **Polimorfik + Fileless (Hafıza İçi + Şifreli)** |
| **Hedef Kapsamı** | Tekil / Basit Ağ | **Enterprise AD / Forest / Cloud** |
| **Genişleme** | Kod Güncellemesi | **Hot-Swap Plugin Sistemi + MCP** |
| **Kod Kalitesi** | Bilinmiyor | **Zero-Defect / Nuclear Tested / Thread Safe** |
| **Kalıcılık** | Basit Persistence | **WMI, Registry, Scheduled Task (Gizli)** |

> **Motto:** "Villager köylüleri yönetir, Drakben kralları devirir."
