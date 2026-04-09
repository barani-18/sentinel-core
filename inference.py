"""
SentinelCore Inference Script
===================================
Connects to the local FastAPI SOC simulator and evaluates using the OpenAI client.
Strictly adheres to the [START], [STEP], and [END] logging format.
Enforces strict LiteLLM proxy routing via os.environ with NO silent failures.
Includes startup retry logic for FastAPI.
"""

import os
import time
import textwrap
import requests
from typing import List, Optional
from openai import OpenAI

# --- Configuration ---
# WE MUST USE os.environ FOR THE PROXY VARIABLES. NO FALLBACKS ALLOWED.
API_BASE_URL = os.environ["API_BASE_URL"]
API_KEY = os.environ["API_KEY"]

MODEL_NAME = os.environ.get("MODEL_NAME", "Qwen/Qwen2.5-72B-Instruct")
TASK_NAME = os.environ.get("MY_ENV_V4_TASK", "soc_investigation")
BENCHMARK = os.environ.get("MY_ENV_V4_BENCHMARK", "sentinel_soc")

# FastAPI Server configuration
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
    print(
        f"[STEP] step={step} action={action} reward={reward:.2f} done={done_val} error={error_val}",
        flush=True,
    )

def log_end(success: bool, steps: int, score: float, rewards: List[float]) -> None:
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(f"[END] success={str(success).lower()} steps={steps} score={score:.3f} rewards={rewards_str}", flush=True)

# --- LLM Interaction ---
def get_model_action(client: OpenAI, step: int, current_state: dict, history: List[str]) -> str:
    """Asks the LLM what action to take based on the current SOC state."""
    history_block = "\n".join(history[-4:]) if history else "None"
    
    prompt = textwrap.dedent(f"""
        You are an autonomous SOC Analyst. 
        Step: {step}
        Current System CPU: {current_state.get('metrics', {}).get('cpu', 'Unknown')}
        Threat Level: {current_state.get('metrics', {}).get('threatLevel', 'Unknown')}
        
        Previous steps:
        {history_block}
        
        Respond with exactly one action word from this list: [investigate, isolate, block, ignore].
        Do not include punctuation or quotes.
    """).strip()

    # NO TRY/EXCEPT AROUND THE PROXY CALL
    completion = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[
            {"role": "system", "content": "You are a cybersecurity AI. Respond with a single action word."},
            {"role": "user", "content": prompt},
        ],
        temperature=TEMPERATURE,
        max_tokens=10,
        timeout=30.0 
    )
    
    text = (completion.choices[0].message.content or "").strip().lower()
    text = text.replace('\n', ' ').replace('\r', '')
    
    valid_actions = ["investigate", "isolate", "block", "ignore"]
    for valid in valid_actions:
        if valid in text:
            return valid
    return "investigate"

# --- Main Evaluation Loop ---
def main() -> None:
    client = OpenAI(
        base_url=API_BASE_URL,
        api_key=API_KEY
    )

    log_start(task=TASK_NAME, env=BENCHMARK, model=MODEL_NAME)

    # 1. Wait for FastAPI to wake up (Retry logic)
    current_state = {}
    max_retries = 15
    for attempt in range(max_retries):
        try:
            reset_resp = requests.post(f"{FASTAPI_URL}/reset", json={}, timeout=5.0)
            reset_resp.raise_for_status()
            current_state = reset_resp.json().get("state", {})
            break # It worked! Exit the retry loop.
        except requests.exceptions.ConnectionError:
            if attempt < max_retries - 1:
                print(f"[DEBUG] Waiting for FastAPI server to start (attempt {attempt + 1}/{max_retries})...", flush=True)
                time.sleep(2) # Wait 2 seconds before trying again
            else:
                print("[DEBUG] FATAL: FastAPI server never started or is crashing.", flush=True)
                log_end(success=False, steps=0, score=0.0, rewards=[])
                return

    history: List[str] = []
    rewards: List[float] = []
    steps_taken = 0
    score = 0.0
    success = False

    try:
        # 2. Run the Simulation Loop
        for step in range(1, MAX_STEPS + 1):
            
            action_kind = get_model_action(client, step, current_state, history)

            resp = requests.post(
                f"{FASTAPI_URL}/api/step",
                json={"kind": action_kind, "alertId": None},
                timeout=10.0
            )
            resp.raise_for_status()
            data = resp.json()
            
            current_state = data.get("state", {})
            reward = float(data.get("reward", 0.0))
            done = bool(data.get("done", False))

            rewards.append(reward)
            steps_taken = step
            history.append(f"Step {step}: {action_kind} -> reward {reward:+.2f}")

            log_step(step=step, action=action_kind, reward=reward, done=done, error=None)

            if done:
                break

        # 3. Calculate Final Score 
        max_possible_reward = MAX_STEPS * 10.0 
        score = sum(rewards) / max_possible_reward if max_possible_reward > 0 else 0.0
        score = min(max(score, 0.0), 1.0) 
        success = score >= SUCCESS_SCORE_THRESHOLD

    finally:
        log_end(success=success, steps=steps_taken, score=score, rewards=rewards)

if __name__ == "__main__":
    main()
