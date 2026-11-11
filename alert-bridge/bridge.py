"""alert-bridge: pulls CloudWatch alarm events from SQS (inside the cluster)
and starts an investigation by calling the kagent agent over A2A.

Why a bridge instead of letting EventBridge call the agent directly?
  * Nothing in the cluster is exposed to the internet (pull, like GitOps).
  * One place for loop-safety rules: cooldown per alarm, max runs per hour.

A2A = Agent-to-Agent protocol (JSON-RPC over HTTP). kagent exposes every
agent at  http://kagent-controller.kagent:8083/api/a2a/<namespace>/<agent>/
"""

from __future__ import annotations

import json
import logging
import os
import signal
import sys
import time
import uuid

import boto3
import httpx

REGION = os.environ.get("AWS_REGION", "us-east-1")
QUEUE_NAME = os.environ.get("QUEUE_NAME", "eks-ai-remediation-alerts")
KAGENT_URL = os.environ.get("KAGENT_URL", "http://kagent-controller.kagent:8083")
AGENT_REF = os.environ.get("AGENT_REF", "kagent/orders-sre")  # namespace/name
COOLDOWN_SECONDS = int(os.environ.get("COOLDOWN_SECONDS", "900"))  # per alarm
MAX_RUNS_PER_HOUR = int(os.environ.get("MAX_RUNS_PER_HOUR", "4"))
AGENT_TIMEOUT_SECONDS = int(os.environ.get("AGENT_TIMEOUT_SECONDS", "600"))

logging.basicConfig(level=logging.INFO, stream=sys.stdout, format="%(message)s")
log = logging.getLogger("alert-bridge")


def audit(event: str, **detail) -> None:
    log.info(json.dumps({"audit_event": event, "component": "alert-bridge", **detail}, default=str))


sqs = boto3.client("sqs", region_name=REGION)
queue_url = sqs.get_queue_url(QueueName=QUEUE_NAME)["QueueUrl"]

_last_run_by_alarm: dict[str, float] = {}
_run_times: list[float] = []
_stop = False


def _handle_sigterm(*_):
    global _stop
    _stop = True


signal.signal(signal.SIGTERM, _handle_sigterm)


def build_prompt(detail: dict) -> str:
    alarm = detail.get("alarmName", "unknown")
    state = detail.get("state", {})
    cfg = detail.get("configuration", {})
    return (
        f"INCIDENT: CloudWatch alarm '{alarm}' changed to ALARM at {state.get('timestamp', 'unknown time')}.\n"
        f"Reason from CloudWatch: {state.get('reason', 'n/a')}\n"
        f"Alarm description: {cfg.get('description', 'n/a')}\n\n"
        "Investigate following your runbook, then either propose exactly one bounded fix "
        "with propose_fix, or explain why no safe automated fix applies. "
        "End with a short summary: root cause, evidence, action taken."
    )


def call_agent(prompt: str) -> str:
    """Send one message to the agent and wait for the final answer (A2A message/send)."""
    namespace, name = AGENT_REF.split("/", 1)
    url = f"{KAGENT_URL}/api/a2a/{namespace}/{name}/"
    payload = {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": "message/send",
        "params": {
            "message": {
                "kind": "message",
                "role": "user",
                "messageId": str(uuid.uuid4()),
                "parts": [{"kind": "text", "text": prompt}],
            },
            "configuration": {"blocking": True},
        },
    }
    # No X-User-Id header: kagent (auth mode "unsecure") then files the session
    # under the default UI user, so you can read the whole run in the kagent UI.
    resp = httpx.post(url, json=payload, timeout=AGENT_TIMEOUT_SECONDS)
    resp.raise_for_status()
    body = resp.json()
    if "error" in body:
        raise RuntimeError(f"A2A error: {body['error']}")
    result = body.get("result", {})

    # The result is a Task (with artifacts/status) or a Message. Collect its text.
    texts: list[str] = []
    for artifact in result.get("artifacts", []) or []:
        texts += [p.get("text", "") for p in artifact.get("parts", []) if p.get("kind") == "text"]
    status_msg = (result.get("status") or {}).get("message") or {}
    texts += [p.get("text", "") for p in status_msg.get("parts", []) if p.get("kind") == "text"]
    texts += [p.get("text", "") for p in result.get("parts", []) or [] if p.get("kind") == "text"]
    return "\n".join(t for t in texts if t).strip() or json.dumps(result)[:2000]


def allowed_to_run(alarm: str) -> tuple[bool, str]:
    now = time.time()
    _run_times[:] = [t for t in _run_times if now - t < 3600]
    if len(_run_times) >= MAX_RUNS_PER_HOUR:
        return False, f"max {MAX_RUNS_PER_HOUR} runs/hour reached"
    last = _last_run_by_alarm.get(alarm)
    if last and now - last < COOLDOWN_SECONDS:
        return False, f"cooldown: last run {int(now - last)}s ago"
    return True, ""


def process(message: dict) -> None:
    event = json.loads(message["Body"])
    detail = event.get("detail", {})
    alarm = detail.get("alarmName", "unknown")
    if detail.get("state", {}).get("value") != "ALARM":
        return

    ok, why = allowed_to_run(alarm)
    if not ok:
        audit("agent_run_skipped", alarm=alarm, detail=why)
        return

    _last_run_by_alarm[alarm] = time.time()
    _run_times.append(time.time())
    audit("agent_run_started", alarm=alarm, agent=AGENT_REF)
    started = time.time()
    try:
        answer = call_agent(build_prompt(detail))
        audit("agent_run_finished", alarm=alarm, seconds=round(time.time() - started), detail=answer[:3000])
    except Exception as exc:  # keep the bridge alive; the alarm can fire again
        audit("agent_run_failed", alarm=alarm, detail=repr(exc)[:500])


def main() -> None:
    log.info("alert-bridge polling %s -> agent %s", queue_url, AGENT_REF)
    while not _stop:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=20)
        for msg in resp.get("Messages", []):
            # Delete first: an alarm is a trigger, not a job to retry forever.
            # If the alarm stays in ALARM, it won't re-fire; you can re-run from the kagent UI.
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            process(msg)
    log.info("alert-bridge stopping")


if __name__ == "__main__":
    main()
