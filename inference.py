import os
import time
import requests
import textwrap
from openai import OpenAI

# ---------------------------------------------------------
# MANDATORY: STRICT PROXY INITIALIZATION
# Verbatim from the validator "How to fix" instructions.
# ---------------------------------------------------------
API_BASE_URL = os.environ["API_BASE_URL"]
API_KEY = os.environ["API_KEY"] 
MODEL_NAME = os.environ.get("MODEL_NAME", "Qwen/Qwen2.5-72B-Instruct")

# Local FastAPI Endpoint
FASTAPI_URL = "http://localhost:8000"

def log_start(task, env, model):
    print(f"[START] task={task} env={env} model={model}", flush=True)

def log_step(step, action, reward, done, error):
    error_val = error if error else "null"
    print(f"[STEP] step={step} action={action} reward={reward:.2f} done={str(done).lower()} error={error_val}", flush=True)

def log_end(success, steps, score, rewards):
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(f"[END] success={str(success).lower()} steps={steps} score={score:.3f} rewards={rewards_str}", flush=True)

def main():
    # 1. Initialize client EXACTLY as requested by the Validator Log
    client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)
    
    log_start("soc_investigation", "sentinel_soc", MODEL_NAME)

    # 2. WAIT FOR SERVER: Prevents "Connection Refused" while FastAPI boots
    current_state = {}
    connected = False
    for i in range(15):
        try:
            # Try to ping your FastAPI reset endpoint
            resp = requests.post(f"{FASTAPI_URL}/reset", json={}, timeout=5)
            if resp.status_code == 200:
                current_state = resp.json().get("state", {})
                connected = True
                break
        except Exception:
            print(f"[DEBUG] Waiting for FastAPI server... (Attempt {i+1}/15)", flush=True)
            time.sleep(3)

    if not connected:
        print("[DEBUG] FATAL: FastAPI server on port 8000 never responded.")
        log_end(False, 0, 0.0, [])
        return

    rewards = []
    # 3. CORE LOOP: Hits the LLM proxy to pass the criteria check
    for step in range(1, 9):
        try:
            # Mandatory LLM call through LiteLLM Proxy
            completion = client.chat.completions.create(
                model=MODEL_NAME,
                messages=[
                    {"role": "system", "content": "You are a SOC AI. Answer with one word: investigate, isolate, block, ignore."},
                    {"role": "user", "content": f"System Metrics: {current_state.get('metrics')}. What is your action?"}
                ],
                max_tokens=10
            )
            action = completion.choices[0].message.content.strip().lower()
            
            # Simple cleanup for valid actions
            action = next((v for v in ["investigate", "isolate", "block", "ignore"] if v in action), "investigate")

            # Execute action via your local FastAPI server
            resp = requests.post(f"{FASTAPI_URL}/api/step", json={"kind": action, "alertId": None})
            resp.raise_for_status()
            data = resp.json()
            
            current_state = data.get("state", {})
            reward = float(data.get("reward", 0.0))
            done = bool(data.get("done", False))
            
            rewards.append(reward)
            log_step(step, action, reward, done, None)
            
            if done: 
                break
        except Exception as e:
            log_step(step, "error", 0.0, True, str(e))
            break

    # Final scoring (Assumes max possible reward is 80)
    final_score = sum(rewards) / 80.0 if rewards else 0.0
    log_end(final_score >= 0.5, len(rewards), final_score, rewards)

if __name__ == "__main__":
    main()
