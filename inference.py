"""
Sentinel-Core Inference Script
===================================
Connects to the Sentinel-Core FastAPI backend and evaluates using the OpenAI client.
Strictly adheres to [START], [STEP], and [END] logging formats.
"""

import os
import time
import requests
import textwrap
from typing import List, Optional
from openai import OpenAI

# --- Configuration ---
# Using os.environ strictly as requested by the validator to ensure proxy routing.
API_BASE_URL = os.environ["API_BASE_URL"]
API_KEY = os.environ["API_KEY"]
MODEL_NAME = os.environ.get("MODEL_NAME", "Qwen/Qwen2.5-72B-Instruct")

# Matches the port in your app.py main() function
FASTAPI_URL = "http://localhost:8000"

def log_start(task, env, model):
    print(f"[START] task={task} env={env} model={model}", flush=True)

def log_step(step, action, reward, done, error):
    error_val = error if error else "null"
    done_val = str(done).lower()
    print(f"[STEP] step={step} action={action} reward={reward:.2f} done={done_val} error={error_val}", flush=True)

def log_end(success, steps, score, rewards):
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(f"[END] success={str(success).lower()} steps={steps} score={score:.3f} rewards={rewards_str}", flush=True)

def main():
    # Initialize OpenAI client with the mandatory environment variables
    client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)
    
    log_start("soc_investigation", "sentinel_soc", MODEL_NAME)

    # 1. WAIT FOR SERVER: Retries until FastAPI is ready (fixes Connection Refused)
    current_state = {}
    connected = False
    for attempt in range(15):
        try:
            # Your server's /reset endpoint
            resp = requests.post(f"{FASTAPI_URL}/reset", json={}, timeout=5.0)
            resp.raise_for_status()
            current_state = resp.json()
            connected = True
            break
        except Exception:
            print(f"[DEBUG] Waiting for Sentinel-Core server... (Attempt {attempt+1}/15)", flush=True)
            time.sleep(3)

    if not connected:
        log_end(False, 0, 0.0, [])
        return

    history: List[str] = []
    rewards: List[float] = []
    steps_taken = 0

    # 2. EVALUATION LOOP
    for step in range(1, 9): # Running for 8 steps
        # Construct prompt based on your server's Metrics model
        metrics = current_state.get("metrics", {})
        prompt = textwrap.dedent(f"""
            System Metrics:
            - Compromised Hosts: {metrics.get('compromisedHosts')}
            - Anomaly Score: {metrics.get('anomalyScore')}
            - CPU Usage: {metrics.get('cpu')}
            - Threat Level: {metrics.get('threatLevel')}

            Choose exactly one action: investigate, isolate_host, block_ip, ignore, escalate, resolve.
        """).strip()

        # LLM Call via Proxy (CRITICAL: Must succeed to pass LLM Criteria Check)
        completion = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": "You are a SOC Analyst AI. Respond with a single action word."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.7,
            max_tokens=15
        )
        
        action_kind = (completion.choices[0].message.content or "").strip().lower()
        
        # Clean up the action to match your Severity/AlertStatus Enums if needed
        # Fallback to 'investigate' if the model rambles
        valid_actions = ["investigate", "isolate_host", "block_ip", "ignore", "escalate", "resolve"]
        final_action = "investigate"
        for v in valid_actions:
            if v in action_kind:
                final_action = v
                break

        # 3. TALK TO SERVER: Corrected from /api/step to /step
        try:
            # Your server's StepRequest model: {"kind": str, "alertId": Optional[str]}
            step_resp = requests.post(
                f"{FASTAPI_URL}/step",
                json={"kind": final_action, "alertId": None},
                timeout=10.0
            )
            step_resp.raise_for_status()
            step_data = step_resp.json()
            
            current_state = step_data.get("state", {})
            reward = float(step_data.get("reward", 0.0))
            done = bool(step_data.get("done", False))
            error = None
        except Exception as e:
            reward = 0.0
            done = True
            error = str(e).replace('\n', ' ')

        # Logging and metrics
        rewards.append(reward)
        steps_taken = step
        log_step(step, final_action, reward, done, error)

        if done:
            break

    # Calculate final score (normalized to 0.0 - 1.0)
    total_reward = sum(rewards)
    score = max(0.0, min(1.0, total_reward / 1.0)) # Adjust normalization as per your scoring logic
    
    log_end(success=(score > 0.5), steps=steps_taken, score=score, rewards=rewards)

if __name__ == "__main__":
    main()
