import os
import requests
import sys
from dotenv import load_dotenv

# Load API key from .env
load_dotenv()
API_KEY = os.getenv("GEMINI_API_KEY")

# Gemini API URL
GEMINI_URL = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={API_KEY}"

def call_gemini(prompt_text):
    headers = {"Content-Type": "application/json"}
    data = {
        "contents": [
            {
                "parts": [{"text": prompt_text}]
            }
        ]
    }

    response = requests.post(GEMINI_URL, headers=headers, json=data)

    if response.status_code == 200:
        result = response.json()
        try:
            print("Gemini Analysis:\n")
            print(result["candidates"][0]["content"]["parts"][0]["text"])
        except Exception:
            print("API call succeeded but failed to extract content.")
    else:
        print("Request failed:", response.status_code, response.text)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Please provide input text to analyze.")
    else:
        call_gemini(sys.argv[1])
