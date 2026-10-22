from dataclasses import dataclass

@dataclass
class Target:
    name: str
    endpoint: str
    model: str