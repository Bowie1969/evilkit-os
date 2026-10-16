"""EvilKit OS — the consolidated, scope-gated operator system.

One control plane for authorized AI security testing: a scope-gated launcher for
the Kimi Code CLI, the heretic/GLM local-model adapters, the harness with its
circuit breakers and evidence journal, the mission contract, and the appliance
seed generator that bakes the whole thing into a bootable drop image.
"""

__version__ = "2.0.0"

BRAIN_NAME = "kimi-k3"
BRAIN_MODEL = "moonshotai/kimi-k3"
BRAIN_URL = "https://openrouter.ai/api/v1"

__all__ = ["__version__", "BRAIN_NAME", "BRAIN_MODEL", "BRAIN_URL"]
