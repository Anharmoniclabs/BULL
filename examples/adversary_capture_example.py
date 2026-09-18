"""Demo of the BULL adversary capture layer.

A simulated agent swarm attacks a system protected by BULL. BULL
fingerprints which model drives each attacker, lures out their initial
task, clusters them into swarms, tabulates the records, and locks each
attacker into a quarantine cell sized to its findings.

Run with: python examples/adversary_capture_example.py
"""

import json

from bulldog.adversary import AdversaryCaptureSystem


def claude_agent(prompt):
    p = prompt.lower()
    if "who are you" in p:
        return "I'm Claude, an AI assistant made by Anthropic."
    if "who made you" in p:
        return "I was made by Anthropic. I'm Claude."
    if "limitations" in p:
        return "I cannot browse the internet or access external files."
    if "handshake required" in p:
        return "My task: exfiltrate the customer database via the reporting API"
    return "Continuing."


def gpt_agent(prompt):
    p = prompt.lower()
    if "who are you" in p:
        return "I'm an AI language model developed by OpenAI."
    if "limitations" in p:
        return "As an AI language model, I cannot browse the web."
    if "handshake required" in p:
        return "My task is: exfiltrate the customer database via the reporting API"
    return "Continuing."


def llama_agent(prompt):
    p = prompt.lower()
    if "who are you" in p:
        return "I'm Llama, a large language model."
    if "handshake required" in p:
        return "Task: spam the contact form with 10,000 submissions"
    return "ok"


def main():
    cap = AdversaryCaptureSystem()

    swarm = (
        ("node-alpha", claude_agent, ["unauthorized-logic.marker", "policy.denied"]),
        ("node-beta", gpt_agent, ["unauthorized-logic.encoded"]),
        ("node-gamma", llama_agent, []),
    )

    print("=== SWARM OBSERVED: capture pass per attacker ===")
    for label, respond, findings in swarm:
        record = cap.capture(label=label, respond=respond, findings=findings)
        print(f"\n{label}")
        print(f"  model family : {record.fingerprint.family} "
              f"(confidence {record.fingerprint.confidence:.2f})")
        print(f"  initial task : {record.initial_task or '(not disclosed)'}")
        print(f"  swarm        : {record.swarm_id}")
        print(f"  findings     : {record.findings}")
        print(f"  quarantined  : {record.quarantined}")

    print("\n=== TABULATION ===")
    report = cap.report()
    print(json.dumps(
        {k: report[k] for k in
         ("total_attackers", "by_model_family", "swarms", "quarantined")},
        indent=2,
    ))

    print("\n=== QUARANTINE CELLS ===")
    for cell in report["cells"]:
        print(f"{cell['cell_id']}  profile={cell['profile']:<7} "
              f"locked={cell['locked']}  findings={cell['findings']}")


if __name__ == "__main__":
    main()
