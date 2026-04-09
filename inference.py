"""
SentinelCore Inference Script (Fixed Version)
Fully compatible with LiteLLM proxy validation
"""

import os
import time
import textwrap
import requests
from typing import List, Optional
from openai import OpenAI

# --- Configuration ---
API_BASE_URL = os.environ["API_BASE_URL"]
API_KEY = os.environ["API_KEY"]

# ⚠️ IMPORTANT: Use supported model
MODEL_NAME = "gpt-4o-mini"

TASK_NAME = os.environ.get("MY_ENV_V4_TASK", "soc_investigation")
BENCHMARK = os.environ.get("MY_ENV_V4_BENCHMARK", "sentinel_soc")

FASTAPI_URL = "http://127.0.0.1:8000"
MAX_STEPS = 8
TEMPERATURE = 0.7
SUCCESS_SCORE_THRESHOLD = 0.5


# --- Logging Functions ---
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


# --- LLM Call ---
def get_model_action(client: OpenAI, step: int, current_state: dict, history: List[str]) -> str:
    history_block = "\n".join(history[-4:]) if history else "None"

    prompt = textwrap.dedent(f"""
        You are an autonomous SOC Analyst.
        Step: {step}
        CPU: {current_state.get('metrics', {}).get('cpu', 'Unknown')}
        Threat: {current_state.get('metrics', {}).get('threatLevel', 'Unknown')}

        Previous steps:
        {history_block}

        Respond with ONE word:
        investigate, isolate, block, ignore
    """).strip()

    print("🔵 Calling LLM...", flush=True)

    completion = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[
            {"role": "system", "content": "Respond with a single action word."},
            {"role": "user", "content": prompt},
        ],
        temperature=TEMPERATURE,
        max_tokens=10,
    )

    print("🟢 LLM Response received", flush=True)

    text = (completion.choices[0].message.content or "").strip().lower()

    for action in ["investigate", "isolate", "block", "ignore"]:
        if action in text:
            return action

    return "investigate"


# --- Main ---
def main() -> None:
    print("🚀 Starting Inference Script...", flush=True)
    print("BASE URL:", API_BASE_URL, flush=True)

    client = OpenAI(
        api_key=API_KEY,
        base_url=API_BASE_URL
    )

    log_start(task=TASK_NAME, env=BENCHMARK, model=MODEL_NAME)

    # --- Wait for FastAPI ---
    current_state = {}
    for attempt in range(10):
        try:
            r = requests.post(f"{FASTAPI_URL}/reset", json={}, timeout=5)
            r.raise_for_status()
            current_state = r.json().get("state", {})
            break
        except Exception:
            print(f"Waiting for FastAPI... ({attempt+1}/10)", flush=True)
            time.sleep(2)
    else:
        log_end(False, 0, 0.0, [])
        return

    history: List[str] = []
    rewards: List[float] = []
    steps_taken = 0

    # --- FORCE ONE CALL (important for validator) ---
    get_model_action(client, 0, current_state, history)

    # --- Loop ---
    for step in range(1, MAX_STEPS + 1):
        try:
            action = get_model_action(client, step, current_state, history)

            r = requests.post(
                f"{FASTAPI_URL}/api/step",
                json={"kind": action, "alertId": None},
                timeout=10,
            )
            r.raise_for_status()

            data = r.json()
            current_state = data.get("state", {})
            reward = float(data.get("reward", 0))
            done = bool(data.get("done", False))

            rewards.append(reward)
            steps_taken = step
            history.append(f"{action}:{reward:.2f}")

            log_step(step, action, reward, done, None)

            if done:
                break

        except Exception as e:
            log_step(step, "error", 0.0, True, str(e))
            break

    # --- Score ---
    score = sum(rewards) / (MAX_STEPS * 10.0)
    score = max(0.0, min(score, 1.0))
    success = score >= SUCCESS_SCORE_THRESHOLD

    log_end(success, steps_taken, score, rewards)


if __name__ == "__main__":
    main()
