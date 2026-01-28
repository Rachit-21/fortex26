import os
import openai

class Validator:
    def __init__(self):
        self.api_key = os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            print("Warning: OPENAI_API_KEY not found.")
        else:
            openai.api_key = self.api_key
            print("AI Validator initialized with OpenAI API key.")

    def validate_vulnerability(self, vulnerability):
        print(f"Validating vulnerability: {vulnerability}")
        return True
