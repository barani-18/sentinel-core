"""
Sentinel-Core Inference Script
===================================
Connects to the local FastAPI backend and evaluates using the OpenAI client.
STRICT COMPLIANCE: Uses the exact minimal pattern required by the hackathon.
"""

import os
import time
import requests
import textwrap
from typing import List, Optional
from openai import OpenAI

# ---------------------------------------------------------
# STRICT MINIMAL PATTERN (Verbatim from Hackathon Rules)
# ---------------------------------------------------------
API_BASE_URL = os.getenv("API_BASE_URL", "https://api.openai.com/v1")
API_KEY = os.getenv("API_KEY")
MODEL_NAME = os.getenv("MODEL_NAME", "gpt-4.1-mini")

if API_KEY is None:
    raise ValueError("API_KEY environment variable is required")

client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)
# ---------------------------------------------------------

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
    log_start("soc_investigation", "sentinel_soc", MODEL_NAME)

    # 1. WAIT FOR SERVER: Retry loop so we don't crash while FastAPI boots up
    current_state = {}
    connected = False
    for attempt in range(15):
        try:
            resp = requests.post(f"{FASTAPI_URL}/reset", json={}, timeout=5.0)
            resp.raise_for_status()
            current_state = resp.json()
            connected = True
            break
        except Exception:
            print(f"[DEBUG] Waiting for Sentinel-Core server... (Attempt {attempt+1}/15)", flush=True)
            time.sleep(3)

    if not connected:
        # If your main.py server crashes, we need to fail cleanly
        log_end(False, 0, 0.0, [])
        return

    history: List[str] = []
    rewards: List[float] = []
    steps_taken = 0

    # 2. THE EVALUATION LOOP
    for step in range(1, 9):
        metrics = current_state.get("metrics", {})
        prompt = textwrap.dedent(f"""
            System Metrics:
            Compromised Hosts: {metrics.get('compromisedHosts')}
            Anomaly Score: {metrics.get('anomalyScore')}
            CPU Usage: {metrics.get('cpu')}
            Threat Level: {metrics.get('threatLevel')}

            Choose exactly one action: investigate, isolate_host, block_ip, ignore, escalate, resolve.
        """).strip()

        # The Mandatory LLM Call through their Proxy
        try:
            completion = client.chat.completions.create(
                model=MODEL_NAME,
                messages=[
                    {"role": "system", "content": "You are a SOC Analyst AI. Respond with a single action word."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.7,
                max_tokens=15,
                timeout=20.0
            )
            action_kind = (completion.choices[0].message.content or "").strip().lower()
        except Exception as e:
            print(f"[DEBUG] LLM Call Failed: {e}", flush=True)
            action_kind = "investigate"

        # Cleanup output
        valid_actions = ["investigate", "isolate_host", "block_ip", "ignore", "escalate", "resolve"]
        final_action = next((v for v in valid_actions if v in action_kind), "investigate")

        # 3. TALK TO YOUR SERVER
        try:
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

        rewards.append(reward)
        steps_taken = step
        log_step(step, final_action, reward, done, error)

        if done:
            break

    # Calculate final score
    score = sum(rewards) / 1.0  # Adjust as needed based on your scoring logic
    score = max(0.0, min(1.0, score)) 
    log_end(success=(score > 0.5), steps=steps_taken, score=score, rewards=rewards)

if __name__ == "__main__":
    main()
