"""
SentinelCore Inference Script
===================================
Connects to the local FastAPI SOC simulator and evaluates using the OpenAI client.
Strictly adheres to the [START], [STEP], and [END] logging format.
Enforces strict LiteLLM proxy routing via os.environ.
"""

import os
import textwrap
import requests
from typing import List, Optional
from openai import OpenAI

# --- Configuration ---
# MODEL_NAME can have a fallback, but keys/URLs MUST NOT.
MODEL_NAME = os.getenv("MODEL_NAME", "Qwen/Qwen2.5-72B-Instruct")
TASK_NAME = os.getenv("MY_ENV_V4_TASK", "soc_investigation")
BENCHMARK = os.getenv("MY_ENV_V4_BENCHMARK", "sentinel_soc")

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

    try:
        completion = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": "You are a cybersecurity AI. Respond with a single action word."},
                {"role": "user", "content": prompt},
            ],
            temperature=TEMPERATURE,
            max_tokens=10,
            timeout=15.0 # Stop infinite hangs!
        )
        text = (completion.choices[0].message.content or "").strip().lower()
        
        # Clean up text to ensure it doesn't break the single-line log rule
        text = text.replace('\n', ' ').replace('\r', '')
        
        # Fallback to 'investigate' if the model rambles
        valid_actions = ["investigate", "isolate", "block", "ignore"]
        for valid in valid_actions:
            if valid in text:
                return valid
        return "investigate"
        
    except Exception as exc:
        print(f"[DEBUG] Model request failed: {exc}", flush=True)
        return "investigate"

# --- Main Evaluation Loop ---
def main() -> None:
    # ---------------------------------------------------------
    # CRITICAL FIX: STRICT LITELLM PROXY COMPLIANCE
    # Using os.environ directly forces the script to use the injected
    # proxy variables without any chance of bypassing them.
    # ---------------------------------------------------------
    try:
        api_base = os.environ["API_BASE_URL"]
        api_key = os.environ["API_KEY"]
    except KeyError as e:
        print(f"[DEBUG] Missing required environment variable for proxy: {e}", flush=True)
        return

    client = OpenAI(
        base_url=api_base,
        api_key=api_key
    )

    history: List[str] = []
    rewards: List[float] = []
    steps_taken = 0
    score = 0.0
    success = False

    log_start(task=TASK_NAME, env=BENCHMARK, model=MODEL_NAME)

    try:
        # 1. Reset the FastAPI Environment
        try:
            reset_resp = requests.post(f"{FASTAPI_URL}/reset", json={}, timeout=10.0)
            reset_resp.raise_for_status()
            current_state = reset_resp.json().get("state", {})
        except Exception as e:
            log_step(1, "reset", 0.0, True, f"Failed to connect to FastAPI: {e}")
            log_end(False, 0, 0.0, [])
            return

        # 2. Run the Simulation Loop
        for step in range(1, MAX_STEPS + 1):
            
            # Ask LLM for the next move via the Proxy
            action_kind = get_model_action(client, step, current_state, history)

            # Send action to FastAPI
            try:
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
                error = None
                
            except Exception as e:
                reward = 0.0
                done = True
                error = f"API Error: {str(e)}"
                error = error.replace('\n', ' ')

            # Record metrics
            rewards.append(reward)
            steps_taken = step
            history.append(f"Step {step}: {action_kind} -> reward {reward:+.2f}")

            # Print exact stdout format required by evaluator
            log_step(step=step, action=action_kind, reward=reward, done=done, error=error)

            if done:
                break

        # 3. Calculate Final Score 
        max_possible_reward = MAX_STEPS * 10.0 
        score = sum(rewards) / max_possible_reward if max_possible_reward > 0 else 0.0
        score = min(max(score, 0.0), 1.0)  # clamp to [0, 1] as required
        success = score >= SUCCESS_SCORE_THRESHOLD

    except Exception as general_error:
        print(f"[DEBUG] Unhandled exception in loop: {general_error}", flush=True)

    finally:
        # Always output the [END] log
        log_end(success=success, steps=steps_taken, score=score, rewards=rewards)


if __name__ == "__main__":
    main()
