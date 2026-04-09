import os
import time
import textwrap
from typing import List
import requests
from openai import OpenAI

API_BASE_URL = os.getenv("API_BASE_URL", "https://api.openai.com/v1")
API_KEY = os.getenv("API_KEY")
MODEL_NAME = os.getenv("MODEL_NAME", "gpt-4.1-mini")
FASTAPI_URL = os.getenv("FASTAPI_URL", "http://localhost:8000")

if API_KEY is None:
    raise ValueError("API_KEY environment variable is required")

client = OpenAI(
    base_url=API_BASE_URL,
    api_key=API_KEY
)


def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)


def log_step(step: int, action: str, reward: float, done: bool, error: str | None) -> None:
    error_val = error if error is not None else "null"
    print(
        f"[STEP] step={step} action={action} reward={reward:.2f} done={str(done).lower()} error={error_val}",
        flush=True,
    )


def log_end(success: bool, steps: int, rewards: List[float]) -> None:
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(
        f"[END] success={str(success).lower()} steps={steps} rewards={rewards_str}",
        flush=True,
    )


def choose_action(metrics: dict) -> str:
    prompt = textwrap.dedent(f"""
        System Metrics:
        - Compromised Hosts: {metrics.get('compromisedHosts')}
        - Anomaly Score: {metrics.get('anomalyScore')}
        - CPU Usage: {metrics.get('cpu')}
        - Threat Level: {metrics.get('threatLevel')}

        Choose exactly one action:
        investigate, isolate_host, block_ip, ignore, escalate, resolve
    """).strip()

    completion = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[
            {"role": "system", "content": "Respond with exactly one action word."},
            {"role": "user", "content": prompt},
        ],
        temperature=0.0,
        max_tokens=10,
    )

    content = (completion.choices[0].message.content or "").strip().lower()
    valid_actions = ["investigate", "isolate_host", "block_ip", "ignore", "escalate", "resolve"]

    for action in valid_actions:
        if action in content:
            return action

    return "investigate"


def main() -> None:
    rewards: List[float] = []
    steps_taken = 0
    success = False
    error_msg = None

    log_start("soc_investigation", "sentinel_soc", MODEL_NAME)

    try:
        current_state = {}
        connected = False

        for _ in range(15):
            try:
                resp = requests.post(f"{FASTAPI_URL}/reset", json={}, timeout=5.0)
                resp.raise_for_status()
                current_state = resp.json()
                connected = True
                break
            except Exception:
                time.sleep(3)

        if not connected:
            return

        for step in range(1, 9):
            metrics = current_state.get("metrics", {})
            action = choose_action(metrics)

            try:
                step_resp = requests.post(
                    f"{FASTAPI_URL}/step",
                    json={"kind": action, "alertId": None},
                    timeout=10.0,
                )
                step_resp.raise_for_status()
                step_data = step_resp.json()

                current_state = step_data.get("state", {})
                reward = float(step_data.get("reward", 0.0))
                done = bool(step_data.get("done", False))
                step_error = None
            except Exception as e:
                reward = 0.0
                done = True
                step_error = str(e).replace("\n", " ")

            rewards.append(reward)
            steps_taken = step
            log_step(step, action, reward, done, step_error)

            if done:
                success = True
                break

    except Exception as e:
        error_msg = str(e).replace("\n", " ")
    finally:
        if steps_taken == 0 and not rewards:
            log_end(False, 0, [])
        else:
            log_end(success, steps_taken, rewards)


if __name__ == "__main__":
    main()
