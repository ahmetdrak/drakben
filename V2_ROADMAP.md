# ⚔️ "VILLAGER KILLER" - Drakben V2.0 Roadmap

Bu yol haritası, Drakben'i sadece bir "araç" olmaktan çıkarıp, **Villager** ve benzeri rakipleri her kulvarda (Zeka, Gizlilik, Envanter, Sızma) geride bırakacak bir "Advanced Persistent Threat (APT)" ajanına dönüştürmek için tasarlanmıştır.

> **Hedef:** Villager'ın "Otomasyonunu" korumak, ancak onun sahip olmadığı "Sürekli Öğrenen Zeka (Self-Refining)" ve "Askeri Düzeyde Gizlilik (Stealth)" yeteneklerini eklemek. Sadece "daha iyi" değil, "algılanamaz" olmak.

---

## 🏗️ Faz 0: REFACTORING & ARCHITECTURAL OVERHAUL (Motor Rektifiye)
*Mevcut Durum: %60 (Tekilleştirme)*
*Hedef: %100 (Mikro-Servis Benzeri Modüler Yapı)*

> *"1500 satırlık dosya = Gelecekteki Kanser."*

- [ ] **Agent Parçalanması (De-Monolithization):**
    - [ ] `refactored_agent.py` (şu an 1700+ satır) dosyasını sorumluluklarına göre bölmek:
        - [ ] `AgentCore.py`: Ana döngü ve orkestrasyon.
        - [ ] `AgentState.py`: Hafıza yönetimi ve durum takibi.
        - [ ] `AgentEvolution.py`: Strateji seçimi ve öğrenme mantığı.
        - [ ] `AgentStealth.py`: WAF atlatma ve gizlilik profilleri.
    - [ ] Bu sayede yeni bir özellik eklemek için tüm ajanı bozma riski ortadan kalkacak.

- [ ] **Dependency Injection:**
    - [ ] `Brain`, `Planner` ve `ToolSelector` modüllerini sıkı bağlı (tight coupling) yapıdan kurtarıp, config üzerinden enjekte edilebilir hale getirmek.

---

## 👻 Faz 1: GHOST PROTOCOL (Gizlilik ve Görünmezlik)
*Mevcut Durum: %90 ✅ (18 test passed)*
*Hedef: %100 (EDR/AV Atlatma ve Dijital İz Bırakmama)*

- [x] **Polimorfik Motor (The Shapeshifter):** ✅ `core/ghost_protocol.py`
    - [x] `AST Transformer`: `PolymorphicTransformer` sınıfı - değişken isimleri, döngü yapıları ve ölü kod (dead code) ekleyerek imza tabanlı taramaları atlatır.
    - [ ] **PyArmor Entegrasyonu:** (İsteğe bağlı - runtime şifreleme)
    - [x] **Obfuscation Pipeline:** `StringEncryptor` (XOR, ROT13, Base64) ile otomatik zincir.

- [x] **Anti-Forensics & Log Cleaning:** ✅ `core/ghost_protocol.py` - `SecureCleanup`
    - [x] Güvenli dosya silme (DoD standartlarında overwrite)
    - [x] Timestomping (Dosya zaman damgalarını manipüle etme)
    - [x] Memory Artifact Cleaning (Bellek kalıntılarını temizleme) ✅ `SecureMemory`
    - [x] **Advanced:** Fileless Execution (Dosyasız çalıştırma - Memory Only) ✅ `MemoryOnlyExecutor`.
    - [x] RAM temizliği (Hassas verilerin bellekten güvenli silinmesi). ✅ `SecureMemory`

---

## 🔫 Faz 2: WEAPON FOUNDRY (Saldırı Envanteri)
*Mevcut Durum: %95 ✅ (27 test passed)*
*Hedef: %100 (Kurumsal Saldırı Seti)*

- [x] **Dinamik Payload Üreticisi:** ✅ `modules/weapon_foundry.py`
    - [x] `WeaponFoundry` + `PayloadGenerator` sınıfları
    - [x] `EncryptionEngine`: XOR, XOR_Multi, AES-256, RC4, ChaCha20 şifreleme
    - [x] **Formatlar:** Python, PowerShell, VBS, HTA, Bash, C, C# ✅

- [x] **C2 (Komuta Kontrol) Mimarisi:** ✅ `modules/c2_framework.py`
    - [x] `ShellcodeTemplates`: Reverse/Bind shell templates ✅
    - [x] HTTP/S (Domain Fronting), DNS Tunneling üzerinden haberleşen beacon'lar. ✅ `DomainFronter` & `DNSTunneler`
    - [x] Heartbeat mekanizması (Ajanın hayatta olduğunu ve durumunu bildirmesi). ✅ `HeartbeatManager`
    - [x] Jitter (Haberleşme aralıklarını rastgeleleştirerek trafik analizini atlatma). ✅ `JitterEngine`

---

## 🧠 Faz 3: HIVE MIND (Kurumsal Zeka & Pivot)
*Mevcut Durum: %85 ✅ (30 test passed)*
*Hedef: %100 (Ağ Topolojisi Analizi ve Yayılma)*

- [x] **Active Directory (AD) Hakimiyeti:** ✅ `modules/hive_mind.py` - `ADAnalyzer`
    - [ ] **Kan İzi Modülü (BloodHound Entegrasyonu):** (Planlanan)
    - [x] Kerberoasting, AS-REP Roasting pattern detection ✅
    - [ ] Impacket kütüphanesinin (psexec, wmiexec, smbexec, secretsdump) native entegrasyonu.

- [x] **Lateral Movement (Yanal Hareket):** ✅ `modules/hive_mind.py` - `LateralMover`
    - [x] Pass-the-Hash (PtH) ve Pass-the-Ticket (PtT) saldırıları. ✅ `ImpacketWrapper`
    - [x] SSH Key Harvesting ve RDP hijacking (Session stealing).
    - [x] Token Impersonation (Yetkili process tokenlarını çalma). ✅ `TokenImpersonator` (modules/ad_extensions.py)
    - [x] BloodHound Integration (Saldırı yolu haritalama). ✅ `BloodHoundAnalyzer` (modules/ad_extensions.py)

---

## 🔌 Faz 4: UNIVERSAL ADAPTER (MCP & Genişleme)
*Mevcut Durum: %95 ✅ (35 test passed)*
*Hedef: %100 (Sınırsız Entegrasyon ve Kendi Kendine Kurulum)*

- [x] **Model Context Protocol (MCP) İstemcisi:** ✅ `core/universal_adapter.py` - `MCPClient`
    - [x] Drakben'i Claude, OpenAI veya yerel LLM'lerin "Tools" yeteneğiyle standart bir protokolle konuşturma ✅
    - [ ] Bu sayede Drakben, dış dünyadaki MCP uyumlu sunucudan (örn: GitHub, Shodan, Jira) veri çekebilir. (Planlanan)
    - [x] MCP Tools: scan, exploit, generate_report ✅

- [x] **Otomatik Araç Kurulumu (Dependency Resolver):** ✅ `DependencyResolver`
    - [x] "Nmap yok mu? İndir ve kur." - TOOL_REGISTRY ile ✅
    - [x] Araçları `tools/` klasörüne izole bir şekilde kuran paket yöneticisi ✅
    - [x] Sistem bağımlılıklarını (apt, pacman, yum, brew, choco) otomatik yönetme ✅

- [x] **API & Headless Mode:** ✅ `APIServer`
    - [x] REST API server with API key management ✅
    - [x] REST API üzerinden emir alma ("Scan this IP") ve sonuç döndürme ✅
    - [x] Full daemon mode (arka plan servisi) ✅ `DaemonService`

---

---

## 🎭 Faz 5: SOCIAL ENGINEERING (İnsan Avcısı - Villager Killer)
*Mevcut Durum: %0 (Konsept)*
*Hedef: %100 (Psikolojik Harp ve Oltalama)*

> *"Makineyi hackleyemiyorsan, insanı hackle."*

- [x] **OSINT Spider (Dijital Ayak İzi):** ✅ `OSINTSpider`
    - [x] LinkedIn, Twitter, Instagram ve Şirket sitelerinden hedef organizasyonun kilit personelini (IT Admin, HR, Finance) çıkarma.
    - [x] E-posta formatı tahmini (`ad.soyad@sirket.com`).

- [x] **Psycho-Profiler (Kişilik Analizi):** ✅ `PsychoProfiler`
    - [x] Hedefin sosyal medya paylaşımlarından psikolojik profilini çıkarma (Öfkeli, Dikkatsiz, Yardımsever).
    - [x] Buna uygun "Spear Phishing" senaryosu üretme.

- [x] **Phishing Generator:** ✅ `PhishingGenerator`
    - [x] Kişiye özel, inandırıcı e-posta ve sahte login sayfaları (Clone) oluşturma.
    - [x] MFA (2FA) bypass teknikleri (Evilginx2 entegrasyonu). ✅ `MFABypass`

---

## 🔮 Faz 6: SINGULARITY (Tam Otonom Kodlama)
*Mevcut Durum: %10 (Code Review)*
*Hedef: %100 (Kendi Silahını Üreten AI)*

> *"Kopyala-yapıştır yapma, üret."*

- [x] **Code Interpreter (Runtime Coding):** ✅ `CodeSynthesizer`
    - [x] Drakben, bir tool bulamadığında "Pes ettim" demez. Python/Bash/Go ile o toolu yazar.
    - [x] Yazdığı toolu sandbox ortamında test eder ve hataları düzeltir. ✅ `CodeValidator`
    - [x] Onaylanırsa saldırıda kullanır ve `custom_tools/` altına kaydeder.

- [x] **WAF/AV Bypass (Mutation):** ✅ `MutationEngine`
    - [x] Gönderilen payload engellenirse, kodu analiz edip tespit edilen imzayı (signature) değiştirir.
    - [x] Obfuscation tekniklerini dinamik olarak uygular.

---

## � Faz 7: THE STRATEGIST (Kurumsal Raporlama)
*Mevcut Durum: %30 (Ham Loglama)*
*Hedef: %100 (C-Level Yönetici Raporları)*

> *"Hacklemek yetmez, anlatabilmek gerekir."*

- [ ] **Dinamik Rapor Motoru:**
    - [ ] Teknik verileri (Nmap XML, Exploit logs) analiz edip, doğal dille (LLM) yönetici özeti yazma.
    - [ ] Şablon Desteği: HTML, PDF, Markdown, JSON formatlarında çıktı.
    - [ ] **Risk Skorlaması:** Bulunan açıkların CVSS skoruna göre işletmeye vereceği zararı hesaplama ("Düşük", "Orta", "Kritik").

---

## �📊 Kıyaslama Tablosu (Hedeflenen)

---

## 🏗️ Faz 8: THE SUPREME PILLARS (Nükleer Temeller & Ölçekleme)
*Mevcut Durum: %0 (Tavsiye / Plan)*
*Hedef: %100 (Kurşun Geçirmez Altyapı)*

- [ ] **Distributed State Management (Complexity Guard):**
    - [ ] Ajan sayısı arttıkça oluşacak "Complexity Explosion"ı engellemek için durum yönetimini (State) **Redis / RabbitMQ** gibi dağıtık sistemlere taşıma.
    - [ ] Bu sayede binlerce eşzamanlı ajan (Swarm Mode) tek bir merkezi beyin (Hive Mind) ile senkronize çalışabilir.

- [ ] **Local LLM Support (⚠️ OPSİYONEL - Zorunlu DEĞİL):**
    - [ ] **Ollama / Llama3 / Mistral** entegrasyonu - **SADECE** güçlü donanıma sahip ve tercih eden kullanıcılar için.
    - [ ] **⚠️ ÖNEMLİ:** API (OpenRouter/OpenAI) **HER ZAMAN** birincil ve varsayılan yöntem olarak kalacak!
    - [ ] **NOT:** Herkesin bilgisayarı yerel LLM çalıştırmaya uygun değildir. Bu özellik opsiyoneldir.
    - [ ] Yerel LLM mevcut değilse veya tercih edilmezse, sistem API kullanmaya devam eder (mevcut davranış korunur).

- [ ] **Docker SDK Sandboxing (Isolaton Guard):**
    - [ ] V2'nin artan gücünü kontrol altında tutmak için tüm operasyonları **Docker SDK** aracılığıyla izole konteynerlarda çalıştırma.
    - [ ] "Sessiz ve Kalıntısız" (Silent & Clean) operasyon: Konteyner silindiğinde tüm saldırı kalıntıları (tools, logs, payloads) fiziksel makineden tamamen silinmiş olur.

---

## 🔬 Faz 9: THE SURGICAL STRIKE (Zero-Day Hunter)
*Mevcut Durum: %0 (Konsept)*
*Hedef: %100 (Otonom Zafiyet Araştırmacısı)*

> *"Kas gücü değil, akıl gücü. Duvarı yıkma, kilidi aç."*

- [x] **AI-Guided Smart Fuzzing (Zeki Avcı):** ✅ `SmartFuzzer` & `TargetAnalyzer`
    - [x] **Critical Path Analysis:** Drakben, fuzzer çalıştırmadan önce hedef uygulamanın logic'ini okur (Reverse Engineering) ve zayıf karnını bulur.
    - [x] **LLM Target Selection:** LLM devreye girer: *"Hey, şurada user_input alan bir fonksiyon var ve boyutu kontrol edilmiyor gibi. Sadece şuraya odaklanalım."*
    - [x] **Surgical Precision:** Drakben 1 milyar rastgele veri basmak yerine, LLM tarafından kurgulanmış **nokta atışı (surgical)** 100 kritik veri setini dener.
    - [x] **Efficiency:** Bu yöntem işlemciyi yormaz, zekayı kullanır. Evdeki PC'yi süper bilgisayar verimliliğine çıkarır.

- [x] **Symbolic Execution (Matematiksel Hack):** ✅ `SymbolicExecutor`
    - [x] Kodun tüm olasılıklarını (binary paths) matematiksel olarak çözüp, hangi girdinin programı çökerteceğini (crash) önceden hesaplar.

---

| Özellik | Villager | DRAKBEN V2.0 (Hedef) |
| :--- | :---: | :---: |
| **Zeka** | LLM Wrapper (Çevirmen) | **Self-Refining (Otonom Karar & Hata Düzeltme)** |
| **Gizlilik** | Standart | **Polimorfik + Fileless (Hafıza İçi + Şifreli)** |
| **Hedef Kapsamı** | Tekil / Basit Ağ | **Enterprise AD / Forest / Cloud** |
| **Genişleme** | Kod Güncellemesi | **Hot-Swap Plugin Sistemi + MCP** |
| **Kod Kalitesi** | Bilinmiyor | **Zero-Defect / Nuclear Tested / Thread Safe** |
| **Altyapı** | Monolitik | **Distributed State (Redis) + Docker Sandbox** |
| **Kalıcılık** | Basit Persistence | **WMI, Registry, Scheduled Task (Gizli)** |
| **Raporlama** | Teknik PDF | **Executive Summary (C-Level Language)** |
| **Sosyal Müh.** | YOK | **OSINT + Phishing + Profiling** |

> **Motto:** "Villager köylüleri yönetir, Drakben kralları devirir."
