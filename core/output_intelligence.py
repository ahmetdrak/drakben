class OutputIntelligence:
    @staticmethod
    def analyze(output: str) -> dict:
        return {
            "category": "generic",
            "summary": output[:200]
        }
