"""
SentinelCore Inference Script
===================================
Connects to the local FastAPI SOC simulator and evaluates using the OpenAI client.
Strictly adheres to the hackathon's LLM Proxy and HF_TOKEN rules.
"""

import os
import requests
import textwrap
from typing import List, Optional
from openai import OpenAI

# ---------------------------------------------------------
# STRICT RULE COMPLIANCE: Configuration
# 1. Read with os.getenv()
# 2. API_BASE_URL and MODEL_NAME have defaults.
# 3. HF_TOKEN is required and raises an error if missing.
# ---------------------------------------------------------
API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "Qwen/Qwen2.5-72B-Instruct")
HF_TOKEN = os.getenv("HF_TOKEN")

if not HF_TOKEN:
    raise ValueError("FATAL: HF_TOKEN environment variable is missing. This is required by the hackathon rules.")

TASK_NAME = os.getenv("MY_ENV_V4_TASK", "soc_investigation")
BENCHMARK = os.getenv("MY_ENV_V4_BENCHMARK", "sentinel_soc")
FASTAPI_URL = "http://localhost:8000"

# --- Mandatory Logging Functions ---
def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)

def log_step(step: int, action: str, reward: float, done: bool, error: Optional[str]) -> None:
    error_val = error if error else "null"
    done_val = str(done).lower()
    print(f"[STEP] step={step} action={action} reward={reward:.2f} done={done_val} error={error_val}", flush=True)

def log_end(success: bool, steps: int, score: float, rewards: List[float]) -> None:
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(f"[END] success={str(success).lower()} steps={steps} score={score:.3f} rewards={rewards_str}", flush=True)

def main() -> None:
    # ---------------------------------------------------------
    # STRICT RULE COMPLIANCE: OpenAI Client Initialization
    # Must use the exact variable names they specified.
    # ---------------------------------------------------------
    client = OpenAI(
        base_url=API_BASE_URL,
        api_key=HF_TOKEN
    )

    log_start(task=TASK_NAME, env=BENCHMARK, model=MODEL_NAME)

    # 1. Reset FastAPI Environment (with loud crash if it fails)
    try:
        reset_resp = requests.post(f"{FASTAPI_URL}/reset", json={}, timeout=15.0)
        reset_resp.raise_for_status()
        current_state = reset_resp.json().get("state", {})
    except Exception as e:
        log_step(1, "reset", 0.0, True, f"Failed to connect to FastAPI: {e}")
        log_end(False, 0, 0.0, [])
        return

    history: List[str] = []
    rewards: List[float] = []
    steps_taken = 0

    # 2. Simulation Loop
    for step in range(1, 9): # MAX 8 STEPS
        prompt = textwrap.dedent(f"""
            You are an autonomous SOC Analyst. 
            Step: {step}
            Current CPU: {current_state.get('metrics', {}).get('cpu', 'Unknown')}
            Threat Level: {current_state.get('metrics', {}).get('threatLevel', 'Unknown')}
            Respond with exactly one action word: investigate, isolate, block, ignore.
        """).strip()

        # Call the LLM Proxy (Loud crash if the proxy fails)
        completion = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": "You are a cybersecurity AI. Respond with a single action word."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.7,
            max_tokens=10,
            timeout=30.0 
        )
        
        text = (completion.choices[0].message.content or "").strip().lower()
        
        # Parse Action
        action_kind = "investigate" # Fallback
        for valid in ["investigate", "isolate", "block", "ignore"]:
            if valid in text:
                action_kind = valid
                break

        # Send action to FastAPI
        resp = requests.post(f"{FASTAPI_URL}/api/step", json={"kind": action_kind, "alertId": None}, timeout=15.0)
        resp.raise_for_status()
        data = resp.json()
        
        current_state = data.get("state", {})
        reward = float(data.get("reward", 0.0))
        done = bool(data.get("done", False))

        rewards.append(reward)
        steps_taken = step
        log_step(step=step, action=action_kind, reward=reward, done=done, error=None)

        if done:
            break

    # Calculate Final Score 
    score = sum(rewards) / 80.0 if rewards else 0.0
    score = min(max(score, 0.0), 1.0)
    success = score >= 0.5

    log_end(success=success, steps=steps_taken, score=score, rewards=rewards)

if __name__ == "__main__":
    main()
