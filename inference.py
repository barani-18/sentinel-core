"""
Minimal Hackathon-Compliant Inference Script
✔ Uses OpenAI Python client
✔ Uses LiteLLM proxy
✔ Uses os.getenv()
✔ Has defaults
✔ HF_TOKEN required
✔ No disallowed SDKs
"""

import os
from openai import OpenAI

# --- Environment Variables ---
API_BASE_URL = os.getenv("API_BASE_URL", "https://api.openai.com/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "gpt-4o-mini")
HF_TOKEN = os.getenv("HF_TOKEN")

# ❗ HF_TOKEN is mandatory
if not HF_TOKEN:
    raise ValueError("HF_TOKEN environment variable is required")

# --- Initialize Client ---
client = OpenAI(
    base_url=API_BASE_URL,
    api_key=HF_TOKEN
)

# --- LLM Call Function ---
def run_inference():
    print("🚀 Running inference...")
    print("Using BASE URL:", API_BASE_URL)
    print("Using MODEL:", MODEL_NAME)

    response = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Say hello in one short sentence."}
        ],
        max_tokens=20,
    )

    output = response.choices[0].message.content.strip()
    print("✅ LLM Output:", output)

    return output


# --- Main ---
if __name__ == "__main__":
    run_inference()
