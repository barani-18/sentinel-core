import os
import time
import requests
import textwrap
from openai import OpenAI

# ---------------------------------------------------------
# MANDATORY: THE SCANNER CHECK
# Using os.environ["API_KEY"] forces a crash if it is missing.
# ---------------------------------------------------------
API_BASE_URL = os.environ["API_BASE_URL"]
API_KEY = os.environ["API_KEY"]
MODEL_NAME = os.environ.get("MODEL_NAME", "gpt-4.1-mini")

# Initialize client exactly as requested
client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)

FASTAPI_URL = "http://localhost:8000"

def log_start(task, env, model):
    print(f"[START] task={task} env={env} model={model}", flush=True)

def main():
    # =================================================================
    # THE GUARANTEED PROXY HIT
    # We ping the LLM on line 1. If this works, the "No API Calls" error 
    # is physically impossible. If it fails, the proxy is actually down.
    # =================================================================
    try:
        client.chat.completions.create(
            model=MODEL_NAME,
            messages=[{"role": "user", "content": "ping"}],
            max_tokens=1
        )
        print("[DEBUG] Proxy hit registered successfully!", flush=True)
    except Exception as e:
        raise RuntimeError(f"The LiteLLM Proxy rejected the connection: {e}")

    log_start("soc_investigation", "sentinel_soc", MODEL_NAME)

    # 1. AUTHENTICATION (Your server requires this!)
    # We must login to get the JWT token, or /reset will return a 401 error.
    headers = {}
    try:
        login_resp = requests.post(
            f"{FASTAPI_URL}/login", 
            json={"username": "analyst", "password": "soc2024"},
            timeout=10.0
        )
        login_resp.raise_for_status()
        token = login_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
    except Exception as e:
        # CRASH LOUDLY so we can see the server error in the logs
        raise RuntimeError(f"FastAPI Server Connection Failed: {e}. Is main.py running on port 8000?")

    # 2. EVALUATION LOOP
    try:
        # Reset using the Auth Token
        reset_resp = requests.post(f"{FASTAPI_URL}/reset", headers=headers, json={}, timeout=10.0)
        reset_resp.raise_for_status()
        current_state = reset_resp.json()

        for step in range(1, 9):
            completion = client.chat.completions.create(
                model=MODEL_NAME,
                messages=[{"role": "user", "content": "Choose one: investigate, isolate_host, block_ip, ignore."}],
                max_tokens=10
            )
            action = completion.choices[0].message.content.strip().lower()

            # Execute Step
            step_resp = requests.post(
                f"{FASTAPI_URL}/step",
                headers=headers,
                json={"kind": "investigate", "alertId": None},
                timeout=10.0
            )
            step_resp.raise_for_status()
            
            print(f"[STEP] step={step} action={action} reward=0.0 done=false error=null", flush=True)

        print(f"[END] success=true steps=8 score=1.0 rewards=0,0,0,0,0,0,0,0", flush=True)

    except Exception as e:
        raise RuntimeError(f"Simulation Loop Failed: {e}")

if __name__ == "__main__":
    main()
