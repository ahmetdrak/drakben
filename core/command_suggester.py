class CommandSuggester:
    @staticmethod
    def suggest(task: str) -> list:
        task = task.lower()
        suggestions = []

        # -----------------------
        # NMAP
        # -----------------------
        if "nmap" in task or "scan" in task:
            suggestions.append({
                "level": "aggressive",
                "command": "nmap -A -T5 target",
                "noise": "high",
                "notes": "Hızlı ama IDS tetikler"
            })

            suggestions.append({
                "level": "balanced",
                "command": "nmap -sS -T3 target",
                "noise": "medium",
                "notes": "Genel kullanım"
            })

            suggestions.append({
                "level": "stealth",
                "command": "nmap -sS -Pn -T2 --scan-delay 1s target",
                "noise": "low",
                "notes": "Daha sessiz, yavaş"
            })

        # -----------------------
        # DIR ENUM
        # -----------------------
        if "dir" in task or "fuzz" in task:
            suggestions.append({
                "level": "stealth",
                "command": "ffuf -u http://target/FUZZ -w wordlist -rate 5",
                "noise": "low",
                "notes": "Düşük hız, az gürültü"
            })

        return suggestions
