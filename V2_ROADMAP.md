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

- [ ] **API & Headless Mode:**
    - [ ] Drakben'i bir arka plan servisi (Daemon) olarak çalıştırma.
    - [ ] REST API üzerinden emir alma ("Scan this IP") ve sonuç döndürme.
    - [ ] Bu sayede başka yazılımlar (örn: SOC Dashboard) Drakben'i tetikleyebilir.

---

---

## 🎭 Faz 5: SOCIAL ENGINEERING (İnsan Avcısı - Villager Killer)
*Mevcut Durum: %0 (Konsept)*
*Hedef: %100 (Psikolojik Harp ve Oltalama)*

> *"Makineyi hackleyemiyorsan, insanı hackle."*

- [ ] **OSINT Spider (Dijital Ayak İzi):**
    - [ ] LinkedIn, Twitter, Instagram ve Şirket sitelerinden hedef organizasyonun kilit personelini (IT Admin, HR, Finance) çıkarma.
    - [ ] E-posta formatı tahmini (`ad.soyad@sirket.com`).

- [ ] **Psycho-Profiler (Kişilik Analizi):**
    - [ ] Hedefin sosyal medya paylaşımlarından psikolojik profilini çıkarma (Öfkeli, Dikkatsiz, Yardımsever).
    - [ ] Buna uygun "Spear Phishing" senaryosu üretme.

- [ ] **Phishing Generator:**
    - [ ] Kişiye özel, inandırıcı e-posta ve sahte login sayfaları (Clone) oluşturma.
    - [ ] MFA (2FA) bypass teknikleri (Evilginx2 entegrasyonu).

---

## 🔮 Faz 6: SINGULARITY (Tam Otonom Kodlama)
*Mevcut Durum: %10 (Code Review)*
*Hedef: %100 (Kendi Silahını Üreten AI)*

> *"Kopyala-yapıştır yapma, üret."*

- [ ] **Code Interpreter (Runtime Coding):**
    - [ ] Drakben, bir tool bulamadığında "Pes ettim" demez. Python/Bash/Go ile o toolu yazar.
    - [ ] Yazdığı toolu sandbox ortamında test eder ve hataları düzeltir.
    - [ ] Onaylanırsa saldırıda kullanır ve `custom_tools/` altına kaydeder.

- [ ] **WAF/AV Bypass (Mutation):**
    - [ ] Gönderilen payload engellenirse, kodu analiz edip tespit edilen imzayı (signature) değiştirir.
    - [ ] Obfuscation tekniklerini dinamik olarak uygular.

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

- [ ] **Local LLM & Performance Optimization (Speed Pillar):**
    - [ ] **Ollama / Llama3 / Misral** entegrasyonlarını "birinci sınıf vatandaş" (First-class citizen) yapmak.
    - [ ] Token maliyetini sıfıra indirmek ve gecikmeyi (latency) minimize etmek için saldırı anında "Edge Inference" (Yerinde Tahminleme) kullanma.

- [ ] **Docker SDK Sandboxing (Isolaton Guard):**
    - [ ] V2'nin artan gücünü kontrol altında tutmak için tüm operasyonları **Docker SDK** aracılığıyla izole konteynerlarda çalıştırma.
    - [ ] "Sessiz ve Kalıntısız" (Silent & Clean) operasyon: Konteyner silindiğinde tüm saldırı kalıntıları (tools, logs, payloads) fiziksel makineden tamamen silinmiş olur.

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
