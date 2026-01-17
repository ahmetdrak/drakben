import re

class InputClassifier:
    @staticmethod
    def classify(text: str) -> str:
        text = text.strip()

        if not text:
            return "empty"

        if re.search(r"[/?|><-]", text):
            return "command"

        if len(text.split()) == 1:
            return "ambiguous"

        return "chat"
