"""
SentinelCore Inference Script
===================================
Connects to the local FastAPI SOC simulator and evaluates using the OpenAI client.
Strictly adheres to the [START], [STEP], and [END] logging format.
NO SAFETY NETS: Forces strict LiteLLM proxy routing.
"""

import os
import requests
from typing import List, Optional
from openai import OpenAI

# 1. STRICT PROXY ENFORCEMENT
# If the grader does not inject these, the script will intentionally crash on line 1.
API_BASE_URL = os.environ["API_BASE_URL"]
API_KEY = os.environ["API_KEY"]

MODEL_NAME = os.environ.get("MODEL_NAME", "Qwen/Qwen2.5-72B-Instruct")
TASK_NAME = os.environ.get("MY_ENV_V4_TASK", "soc_investigation")
BENCHMARK = os.environ.get("MY_ENV_V4_BENCHMARK", "sentinel_soc")

FASTAPI_URL = "http://localhost:8000"
MAX_STEPS = 8
TEMPERATURE = 0.7
MAX_TOKENS = 150
SUCCESS_SCORE_THRESHOLD = 0.5

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
    # 2. EXACT PROXY INITIALIZATION (Matches grader instructions verbatim)
    client = OpenAI(
        base_url=os.environ["API_BASE_URL"],
        api_key=os.environ["API_KEY"]
    )

    log_start(task=TASK_NAME, env=BENCHMARK, model=MODEL_NAME)

    # 3. NO SAFETY NET AROUND FASTAPI
    # If the server isn't running, this crashes and gives us the real error!
    reset_resp = requests.post(f"{FASTAPI_URL}/reset", json={}, timeout=15.0)
    reset_resp.raise_for_status()
    current_state = reset_resp.json().get("state", {})

    history: List[str] = []
    rewards: List[float] = []
    steps_taken = 0

    # 4. SIMULATION LOOP
    for step in range(1, MAX_STEPS + 1):
        
        # Prepare Prompt
        prompt = (f"Step: {step}. CPU: {current_state.get('metrics', {}).get('cpu')}. "
                  f"Threat Level: {current_state.get('metrics', {}).get('threatLevel')}. "
                  "Respond with one word: investigate, isolate, block, or ignore.")

        # NO SAFETY NET AROUND LLM PROXY
        completion = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": "You are a cybersecurity AI. Respond with a single action word."},
                {"role": "user", "content": prompt},
            ],
            temperature=TEMPERATURE,
            max_tokens=10,
            timeout=20.0 
        )
        
        text = (completion.choices[0].message.content or "").strip().lower()
        
        # Determine Action
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

        # Record metrics
        rewards.append(reward)
        steps_taken = step
        history.append(f"Step {step}: {action_kind} -> reward {reward:+.2f}")

        log_step(step=step, action=action_kind, reward=reward, done=done, error=None)

        if done:
            break

    # Calculate Score 
    max_possible_reward = MAX_STEPS * 10.0 
    score = sum(rewards) / max_possible_reward if max_possible_reward > 0 else 0.0
    score = min(max(score, 0.0), 1.0)
    success = score >= SUCCESS_SCORE_THRESHOLD

    log_end(success=success, steps=steps_taken, score=score, rewards=rewards)


if __name__ == "__main__":
    main()
