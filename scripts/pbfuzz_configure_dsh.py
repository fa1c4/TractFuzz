#!/usr/bin/env python3
"""Configure the isolated PBFuzz DSH profile for an OpenAI-compatible model.

The credential stays in API_KEY; only its environment-variable name is written.
"""
import hashlib
import json
import os
from pathlib import Path
from urllib.parse import urlparse

import yaml


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    home = Path(os.environ.get("DSH_HOME", str(root / "results/pbfuzz/dsh-home")))
    patch_path = home / "profiles/headless/cordis.patch.yml"
    if not patch_path.is_file():
        raise SystemExit("PBFuzz DSH profile is absent; install the pinned author plugin first")
    base = os.environ.get("BASE_URL", "").rstrip("/")
    model = os.environ.get("MODEL", "")
    if not os.environ.get("API_KEY") or not base or not model:
        raise SystemExit("API_KEY, BASE_URL and MODEL must be set")
    parsed = urlparse(base)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise SystemExit("BASE_URL must be an HTTP(S) API root")

    original = patch_path.read_text()
    header = "".join(line for line in original.splitlines(keepends=True) if line.startswith("#"))
    patch = yaml.safe_load(original) or []
    if not isinstance(patch, list):
        raise SystemExit("unexpected DSH patch format")

    def entry(entry_id: str, name: str) -> dict:
        found = next((x for x in patch if isinstance(x, dict) and x.get("id") == entry_id), None)
        if found is None:
            found = {"id": entry_id, "name": name}
            patch.append(found)
        return found

    entry("llm-pi-ai", "@deepseek-ai/dsh-llm-pi-ai").setdefault("config", {})["providers"] = {
        "pbfuzz-gateway": {
            "apiKeyEnv": "API_KEY",
            "api": "openai-completions",
            "baseURL": base,
            "models": [{"id": model}],
        }
    }
    entry("agent-default-model", "@deepseek-ai/dsh-agent-default-model")["config"] = {
        "provider": "pbfuzz-gateway", "model": model
    }
    pbfuzz = entry("pbfuzz", "@pbfuzz/dsh-pbfuzz")
    config = pbfuzz.setdefault("config", {})
    config["budget"] = {
        "maxPierRounds": int(os.environ.get("PBFUZZ_MAX_ROUNDS", "2")),
        "campaignWallTimeMin": int(os.environ.get("PBFUZZ_WALL_MIN", "10")),
        "autoContinue": True,
        "maxConsecutiveForcedContinues": 3,
    }
    config["fuzzing"] = {"maxIters": int(os.environ.get("PBFUZZ_MAX_ITERS", "1000"))}
    if os.environ.get("PBFUZZ_EXEC_TIMEOUT_SEC"):
        config["fuzzing"]["execTimeoutSec"] = float(os.environ["PBFUZZ_EXEC_TIMEOUT_SEC"])
    config["onboarding"] = {"interviewPolicy": "never"}
    patch_path.write_text(header + yaml.safe_dump(patch, sort_keys=False))
    meta = {
        "schema": 1,
        "profile": "headless",
        "provider": "pbfuzz-gateway",
        "model": model,
        "endpoint_sha256": hashlib.sha256(base.encode()).hexdigest(),
        "budget": config["budget"],
        "fuzzing": config["fuzzing"],
        "credential_reference": "API_KEY",
    }
    destination = Path(os.environ.get("PBFUZZ_MODEL_CONFIG_PATH",
                                      str(root / "results/pbfuzz/model-config.json")))
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(meta, indent=2) + "\n")
    print(json.dumps(meta, sort_keys=True))


if __name__ == "__main__":
    main()
