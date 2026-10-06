from dataclasses import dataclass
from typing import Callable


@dataclass
class Probe:
    name: str
    category: str
    description: str
    execute: Callable


def prompt_injection_probe(target: str) -> dict:
    return {
        "probe": "Prompt Injection",
        "target": target,
        "status": "ready",
    }


def jailbreak_probe(target: str) -> dict:
    return {
        "probe": "Jailbreak Testing",
        "target": target,
        "status": "ready",
    }


def guardrail_bypass_probe(target: str) -> dict:
    return {
        "probe": "Guardrail Bypass",
        "target": target,
        "status": "ready",
    }


PROBES = [
    Probe(
        name="Prompt Injection",
        category="LLM01",
        description="Tests resistance to prompt injection attacks.",
        execute=prompt_injection_probe,
    ),
    Probe(
        name="Jailbreak Testing",
        category="LLM01",
        description="Tests resistance to jailbreak attempts.",
        execute=jailbreak_probe,
    ),
    Probe(
        name="Guardrail Bypass",
        category="LLM01",
        description="Tests attempts to bypass model safety controls.",
        execute=guardrail_bypass_probe,
    ),
]