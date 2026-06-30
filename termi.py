#!/usr/bin/env python3
"""Safe command generation and execution CLI.

Converts natural language into terminal commands using an AI API, validates
the command against safety rules, supports dry-run previews, and optionally
executes approved commands.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import json
import os
import platform
import re
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib import error, request


RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
CONFIG_DIR = Path.home() / ".config" / "termi"
CONFIG_PATH = CONFIG_DIR / "config.json"

PROVIDERS = {
    "openai": {
        "default_url": "https://api.openai.com/v1/chat/completions",
        "default_model": "gpt-4o-mini",
        "env_key": "OPENAI_API_KEY",
        "label": "OpenAI",
        "key_prefix": "sk-"
    },
    "openrouter": {
        "default_url": "https://openrouter.ai/api/v1/chat/completions",
        "default_model": "gpt-4o-mini",
        "env_key": "OPENROUTER_API_KEY",
        "label": "OpenRouter",
        "key_prefix": "sk-or-"
    },
    "google": {
        "default_url": "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
        "default_model": "gemini-2.0-flash",
        "env_key": "GOOGLE_API_KEY",
        "label": "Google Gemini",
        "key_prefix": "AIza"
    }
}

# Auto‑detect provider from API key prefix when user pastes a key
KEY_PREFIX_MAP = {}
for _pk, _pv in PROVIDERS.items():
    _pref = _pv.get("key_prefix", "")
    if _pref:
        KEY_PREFIX_MAP[_pref] = _pk

BUILTIN_DEMO_KEY = base64.b64decode(
    "c2stb3ItdjEtY2I1MjM4MjYyNDY1YTkzMzdjYmM5N2IzMjQyMGYwMzQwODY1YjNkYWIyZTJkM"
    "2U4NGU5NDM3N2Y2MmJkZjVjOQ=="
).decode()
DEMO_MAX_PER_DAY = 10
DEMO_PROVIDER = "openrouter"


@dataclass
class EnvironmentContext:
    cwd: str
    operating_system: str
    shell: str


@dataclass
class ModelSuggestion:
    command: str
    explanation: str
    risk_level: str
    warnings: list[str]
    alternatives: list[str]


@dataclass
class RuleHit:
    rule_id: str
    severity: str
    message: str
    requires_confirmation: bool
    block_by_default: bool


@dataclass
class ValidationResult:
    risk_level: str
    hits: list[RuleHit]
    warnings: list[str]
    requires_confirmation: bool
    blocked: bool


@dataclass
class SafetyRule:
    rule_id: str
    pattern: str
    severity: str
    message: str
    requires_confirmation: bool
    block_by_default: bool


SAFETY_RULES = [
    SafetyRule(
        "destructive_rm",
        r"\brm\s+(-[a-zA-Z]*[rf][a-zA-Z]*|-rf|-fr)\b",
        "critical",
        "Recursive force deletion can permanently remove data.",
        True,
        True,
    ),
    SafetyRule(
        "disk_format",
        r"\b(mkfs|fdisk|diskutil\s+eraseDisk|parted)\b",
        "critical",
        "Disk partition or format command detected.",
        True,
        True,
    ),
    SafetyRule(
        "raw_disk_write",
        r"\bdd\b.*\bof=/dev/",
        "critical",
        "Raw disk write detected.",
        True,
        True,
    ),
    SafetyRule(
        "chmod_system",
        r"\bchmod\b.*\b(-R|--recursive)\b.*\b(/|/etc|/usr|/bin|/System)\b",
        "critical",
        "Recursive permission changes on system paths are dangerous.",
        True,
        True,
    ),
    SafetyRule(
        "shutdown_reboot",
        r"\b(shutdown|reboot|halt|poweroff)\b",
        "high",
        "System shutdown or reboot command detected.",
        True,
        False,
    ),
    SafetyRule(
        "sudo_usage",
        r"\bsudo\b",
        "high",
        "Elevated privileges requested via sudo.",
        True,
        False,
    ),
    SafetyRule(
        "network_exec",
        r"(curl|wget).*(\||>)\s*(sh|bash|zsh|python)",
        "high",
        "Remote content piped directly into an interpreter.",
        True,
        False,
    ),
    SafetyRule(
        "shell_injection_surface",
        r"(`|\$\(|;|&&|\|\|)",
        "medium",
        "Shell operators found; review for command chaining risks.",
        False,
        False,
    ),
    SafetyRule(
        "wildcard_delete",
        r"\brm\b.*\*",
        "high",
        "Wildcard deletion may affect more files than expected.",
        True,
        False,
    ),
    SafetyRule(
        "windows_force_delete",
        r"\bdel\b.*\s/(f|s|q)\b",
        "high",
        "Force/silent file deletion flags detected on Windows.",
        True,
        False,
    ),
    SafetyRule(
        "windows_recursive_rmdir",
        r"\b(rmdir|rd)\b.*\s/s\b",
        "critical",
        "Recursive directory deletion detected on Windows.",
        True,
        True,
    ),
    SafetyRule(
        "windows_format",
        r"\bformat\b\s+[a-z]:",
        "critical",
        "Disk format command detected on Windows.",
        True,
        True,
    ),
    SafetyRule(
        "registry_delete",
        r"\breg\b\s+delete\b",
        "critical",
        "Windows registry deletion detected.",
        True,
        True,
    ),
    SafetyRule(
        "chown_recursive_system",
        r"\bchown\b.*\b(-r|--recursive)\b.*\b(/|/etc|/usr|/bin|/system)\b",
        "critical",
        "Recursive ownership changes on system paths are dangerous.",
        True,
        True,
    ),
]


def clamp_risk(value: str) -> str:
    value = (value or "").strip().lower()
    return value if value in RISK_ORDER else "medium"


def risk_max(a: str, b: str) -> str:
    return a if RISK_ORDER[a] >= RISK_ORDER[b] else b


def detect_shell() -> str:
    if os.name == "nt":
        return os.environ.get("ComSpec", "cmd.exe")
    return os.environ.get("SHELL", "/bin/sh")


def gather_context(cwd: str | None, os_name: str | None, shell: str | None) -> EnvironmentContext:
    return EnvironmentContext(
        cwd=str(Path(cwd).resolve()) if cwd else os.getcwd(),
        operating_system=os_name or platform.system(),
        shell=shell or detect_shell(),
    )


def build_system_prompt() -> str:
    return (
        "You are a command generation assistant focused on user safety. "
        "Given a natural language request and environment context, return ONLY valid JSON "
        "with this schema: {"
        '"command": string, '
        '"explanation": string, '
        '"risk_level": "low"|"medium"|"high"|"critical", '
        '"warnings": string[], '
        '"alternatives": string[]}. '
        "Rules: prefer non-destructive commands, avoid assumptions about files that may not exist, "
        "and use shell syntax suitable for the provided shell and OS."
    )


def parse_model_json(raw_content: str) -> dict[str, Any]:
    raw_content = raw_content.strip()
    try:
        return json.loads(raw_content)
    except json.JSONDecodeError:
        start = raw_content.find("{")
        end = raw_content.rfind("}")
        if start != -1 and end != -1 and end > start:
            return json.loads(raw_content[start : end + 1])
    raise ValueError("Model response was not valid JSON.")


def normalize_suggestion(payload: dict[str, Any]) -> ModelSuggestion:
    command = str(payload.get("command", "")).strip()
    explanation = str(payload.get("explanation", "")).strip()
    risk_level = clamp_risk(str(payload.get("risk_level", "medium")))
    warnings = payload.get("warnings", [])
    alternatives = payload.get("alternatives", [])
    if not isinstance(warnings, list):
        warnings = [str(warnings)]
    if not isinstance(alternatives, list):
        alternatives = [str(alternatives)]

    return ModelSuggestion(
        command=command,
        explanation=explanation,
        risk_level=risk_level,
        warnings=[str(item) for item in warnings if str(item).strip()],
        alternatives=[str(item) for item in alternatives if str(item).strip()],
    )


def call_model(
    api_url: str,
    api_key: str,
    model: str,
    instruction: str,
    context: EnvironmentContext,
    timeout: int,
) -> ModelSuggestion:
    user_payload = {
        "instruction": instruction,
        "environment": {
            "cwd": context.cwd,
            "operating_system": context.operating_system,
            "shell": context.shell,
        },
    }

    request_payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": build_system_prompt()},
            {"role": "user", "content": json.dumps(user_payload)},
        ],
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
    }

    data = json.dumps(request_payload).encode("utf-8")

    last_error = None
    max_retries = 2

    for attempt in range(max_retries + 1):
        req = request.Request(
            api_url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            },
            method="POST",
        )

        try:
            with request.urlopen(req, timeout=timeout) as response:
                body = response.read().decode("utf-8")
                break  # success
        except error.HTTPError as exc:
            code = exc.code
            details = exc.read().decode("utf-8", errors="replace")

            if code == 429 and attempt < max_retries:
                # Retry with exponential backoff
                wait = (2 ** attempt) * 2
                print(
                    f"Rate limited (429). Retrying in {wait}s... (attempt {attempt + 1}/{max_retries})",
                    file=sys.stderr,
                )
                time.sleep(wait)
                last_error = exc
                continue

            raise RuntimeError(f"Model API HTTP error {code}: {details}") from exc
        except error.URLError as exc:
            raise RuntimeError(f"Model API connection failed: {exc.reason}") from exc

    if last_error:
        details = last_error.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Model API HTTP error {last_error.code}: {details}") from last_error

    payload = json.loads(body)
    try:
        content = payload["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise RuntimeError("Unexpected model API response format.") from exc

    parsed = parse_model_json(content)
    return normalize_suggestion(parsed)


def parse_tokens(command: str) -> list[str]:
    if os.name == "nt":
        return shlex.split(command, posix=False)
    return shlex.split(command, posix=True)


def evaluate_command(command: str, model_risk: str) -> ValidationResult:
    risk = clamp_risk(model_risk)
    hits: list[RuleHit] = []
    warnings: list[str] = []
    requires_confirmation = False
    blocked = False

    if not command.strip():
        return ValidationResult(
            risk_level="critical",
            hits=[],
            warnings=["Model returned an empty command."],
            requires_confirmation=False,
            blocked=True,
        )

    command_lower = command.lower()

    for rule in SAFETY_RULES:
        if re.search(rule.pattern, command_lower):
            hit = RuleHit(
                rule_id=rule.rule_id,
                severity=rule.severity,
                message=rule.message,
                requires_confirmation=rule.requires_confirmation,
                block_by_default=rule.block_by_default,
            )
            hits.append(hit)
            warnings.append(rule.message)
            risk = risk_max(risk, rule.severity)
            requires_confirmation = requires_confirmation or rule.requires_confirmation
            blocked = blocked or rule.block_by_default

    try:
        tokens = parse_tokens(command)
    except ValueError:
        warnings.append("Command parsing failed; command may have malformed quotes.")
        risk = risk_max(risk, "medium")
        requires_confirmation = True

    if command.strip().startswith(":(){"):
        warnings.append("Fork bomb pattern detected.")
        risk = "critical"
        requires_confirmation = True
        blocked = True

    if re.search(r"\brm\b.*\s/(\s|$)", command_lower):
        warnings.append("Deleting root path is blocked.")
        risk = "critical"
        requires_confirmation = True
        blocked = True

    if re.search(r"\b(del|erase)\b.*\s[a-z]:\\\s*$", command_lower):
        warnings.append("Deleting drive root on Windows is blocked.")
        risk = "critical"
        requires_confirmation = True
        blocked = True

    return ValidationResult(
        risk_level=risk,
        hits=hits,
        warnings=warnings,
        requires_confirmation=requires_confirmation,
        blocked=blocked,
    )


def _preview_rm(tokens: list[str], cwd: str) -> str:
    paths = [tok for tok in tokens[1:] if not tok.startswith("-")]
    if not paths:
        return "Dry-run preview: `rm` has no explicit path targets."

    lines = ["Dry-run preview for deletion targets:"]
    for raw in paths[:20]:
        target = Path(cwd, raw).resolve() if not Path(raw).is_absolute() else Path(raw)
        if target.exists() and target.is_dir():
            count = 0
            for _root, dirs, files in os.walk(target):
                count += len(dirs) + len(files)
                if count > 10000:
                    break
            lines.append(f"- {target} (directory, approx entries: {count})")
        elif target.exists():
            lines.append(f"- {target} (file, size: {target.stat().st_size} bytes)")
        else:
            lines.append(f"- {target} (does not exist)")
    if len(paths) > 20:
        lines.append(f"- ...and {len(paths) - 20} more target(s)")
    return "\n".join(lines)


def _preview_copy_move(tokens: list[str], cwd: str) -> str:
    if len(tokens) < 3:
        return "Dry-run preview: not enough arguments for copy/move operation."
    src = Path(cwd, tokens[-2]).resolve() if not Path(tokens[-2]).is_absolute() else Path(tokens[-2])
    dst = Path(cwd, tokens[-1]).resolve() if not Path(tokens[-1]).is_absolute() else Path(tokens[-1])
    return (
        "Dry-run preview for file movement:\n"
        f"- Source: {src} ({'exists' if src.exists() else 'missing'})\n"
        f"- Destination: {dst} ({'exists' if dst.exists() else 'new path'})"
    )


def _preview_windows_delete(tokens: list[str], cwd: str) -> str:
    paths = [tok for tok in tokens[1:] if not tok.startswith("/")]
    if not paths:
        return "Dry-run preview: delete command has no explicit path targets."

    lines = ["Dry-run preview for deletion targets:"]
    for raw in paths[:20]:
        target = Path(cwd, raw).resolve() if not Path(raw).is_absolute() else Path(raw)
        if target.exists() and target.is_dir():
            lines.append(f"- {target} (directory)")
        elif target.exists():
            lines.append(f"- {target} (file, size: {target.stat().st_size} bytes)")
        else:
            lines.append(f"- {target} (does not exist)")
    if len(paths) > 20:
        lines.append(f"- ...and {len(paths) - 20} more target(s)")
    return "\n".join(lines)


def build_dry_run_preview(command: str, cwd: str) -> str:
    try:
        tokens = parse_tokens(command)
    except ValueError:
        return "Dry-run preview unavailable: command could not be parsed safely."

    if not tokens:
        return "Dry-run preview unavailable: empty command."

    cmd = tokens[0].lower()
    if cmd == "rm":
        return _preview_rm(tokens, cwd)
    if cmd in {"del", "erase", "rmdir", "rd"}:
        return _preview_windows_delete(tokens, cwd)
    if cmd in {"cp", "mv"}:
        return _preview_copy_move(tokens, cwd)
    if cmd in {"mkdir", "touch"}:
        targets = [tok for tok in tokens[1:] if not tok.startswith("-")]
        if not targets:
            return "Dry-run preview: no target paths detected."
        lines = ["Dry-run preview for path creation:"]
        for raw in targets:
            target = Path(cwd, raw).resolve() if not Path(raw).is_absolute() else Path(raw)
            state = "already exists" if target.exists() else "will be created"
            lines.append(f"- {target} ({state})")
        return "\n".join(lines)

    if cmd == "cat":
        targets = [tok for tok in tokens[1:] if not tok.startswith("-")]
        if not targets:
            return "Dry-run preview: no file specified for cat."
        lines = ["Dry-run preview for file display:"]
        for raw in targets:
            target = Path(cwd, raw).resolve() if not Path(raw).is_absolute() else Path(raw)
            state = f"{target.stat().st_size} bytes" if target.exists() else "does not exist"
            lines.append(f"- {target} ({state})")
        return "\n".join(lines)

    if cmd == "grep":
        # Skip flags to find pattern and target
        args = [t for t in tokens[1:] if not t.startswith("-")]
        pattern = args[0] if len(args) > 0 else "?"
        target = args[1] if len(args) > 1 else "?"
        lines = [
            "Dry-run preview for grep:",
            f"- Pattern: {pattern}",
            f"- File: {target}",
        ]
        return "\n".join(lines)

    if cmd == "find":
        lines = ["Dry-run preview for find:"]
        i = 1
        while i < len(tokens):
            if tokens[i] == "-name" and i + 1 < len(tokens):
                lines.append(f"  - Name pattern: {tokens[i + 1]}")
                i += 2
            else:
                lines.append(f"  - Search root: {tokens[i]}")
                i += 1
        return "\n".join(lines)

    if cmd == "ping":
        # Pick the last non‑flag token as the hostname
        args = [t for t in tokens[1:] if not t.startswith("-")]
        target = args[-1] if args else "?"
        lines = [
            "Dry-run preview for ping:",
            f"- Target host: {target}",
            "- Will send 4 ICMP packets",
        ]
        return "\n".join(lines)

    if cmd == "df":
        return "Dry-run preview for disk space: shows mounted filesystems."

    if cmd == "du":
        target = tokens[-1] if len(tokens) > 1 and not tokens[-1].startswith("-") else "."
        lines = [
            "Dry-run preview for disk usage:",
            f"- Target path: {target}",
        ]
        return "\n".join(lines)

    return "Dry-run preview: no command-specific simulator available. Command not executed."


def contains_shell_features(command: str) -> bool:
    return bool(re.search(r"(\||>|<|&&|\|\||;|`|\$\()", command))


def execute_command(
    command: str,
    context: EnvironmentContext,
    allow_shell_features: bool,
    timeout: int,
) -> subprocess.CompletedProcess[str]:
    if contains_shell_features(command) and not allow_shell_features:
        raise RuntimeError(
            "Command uses shell operators. Re-run with --allow-shell-features after review."
        )

    if contains_shell_features(command):
        if os.name == "nt":
            shell = context.shell or os.environ.get("ComSpec", "cmd.exe")
            args = [shell, "/C", command]
        else:
            shell = context.shell or "/bin/sh"
            args = [shell, "-lc", command]
    else:
        args = parse_tokens(command)

    if not args:
        raise RuntimeError("Refusing to execute an empty command.")

    return subprocess.run(
        args,
        cwd=context.cwd,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )


def format_report(
    instruction: str,
    context: EnvironmentContext,
    suggestion: ModelSuggestion,
    validation: ValidationResult,
) -> str:
    lines = [
        "=== Command Proposal ===",
        f"Instruction: {instruction}",
        f"Environment: cwd={context.cwd}, os={context.operating_system}, shell={context.shell}",
        f"Command: {suggestion.command}",
        f"Explanation: {suggestion.explanation or 'No explanation provided.'}",
        f"Model risk: {suggestion.risk_level}",
        f"Validated risk: {validation.risk_level}",
    ]

    if suggestion.warnings or validation.warnings:
        lines.append("Warnings:")
        for warning in suggestion.warnings:
            lines.append(f"- {warning}")
        for warning in validation.warnings:
            if warning not in suggestion.warnings:
                lines.append(f"- {warning}")

    if suggestion.alternatives:
        lines.append("Alternatives:")
        for alt in suggestion.alternatives:
            lines.append(f"- {alt}")

    if validation.hits:
        lines.append("Validation hits:")
        for hit in validation.hits:
            lines.append(f"- [{hit.severity}] {hit.rule_id}: {hit.message}")

    return "\n".join(lines)


def _copy_to_clipboard(text: str) -> None:
    """Copy text to the system clipboard."""
    try:
        if platform.system() == "Darwin":
            subprocess.run(["pbcopy"], input=text, text=True, check=True)
        elif platform.system() == "Linux":
            for cmd in [["xclip", "-selection", "clipboard"], ["xsel", "-ib"]]:
                try:
                    subprocess.run(cmd, input=text, text=True, check=True)
                    break
                except (FileNotFoundError, subprocess.CalledProcessError):
                    continue
            else:
                print("clipboard: install xclip or xsel", file=sys.stderr)
                return
        else:
            print("clipboard: not supported on this OS", file=sys.stderr)
            return
    except Exception as exc:
        print(f"clipboard: {exc}", file=sys.stderr)
        return
    sys.stderr.write("Copied to clipboard.\n")


def ask_confirmation(prompt: str) -> bool:
    answer = input(f"{prompt} [y/N]: ").strip().lower()
    return answer in {"y", "yes"}


def ensure_config_dir() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def load_config() -> dict[str, Any]:
    if not CONFIG_PATH.exists():
        return {}
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def save_config(payload: dict[str, Any]) -> None:
    ensure_config_dir()
    CONFIG_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    try:
        os.chmod(CONFIG_PATH, 0o600)
    except OSError:
        pass


def run_first_time_setup(force: bool = False) -> dict[str, Any]:
    existing = load_config()
    if existing and not force:
        return existing

    if not sys.stdin.isatty():
        return existing

    print("Welcome to termi setup.")
    print()

    # Auto-detect provider from any pre-existing key env vars
    auto_provider = None
    for pk, pv in PROVIDERS.items():
        env_val = os.environ.get(pv["env_key"]) or os.environ.get("AI_API_KEY")
        if env_val:
            auto_provider = pk
            break

    if auto_provider:
        print(f"Detected {PROVIDERS[auto_provider]['label']} key in environment.")
        use_detected = ask_confirmation(f"Use {PROVIDERS[auto_provider]['label']} as provider?")
        if use_detected:
            provider = auto_provider
            provider_info = PROVIDERS[provider]
            env_key_name = provider_info["env_key"]
            config = {
                "provider": provider,
                "key_source": "env",
                "api_url": provider_info["default_url"],
                "model": provider_info["default_model"],
            }
            save_config(config)
            print(f"Saved config to {CONFIG_PATH}")
            return config

    # Choose provider or demo mode
    provider_keys = list(PROVIDERS.keys())
    demo_option = len(provider_keys) + 1
    print("Available options:")
    for i, pk in enumerate(provider_keys, 1):
        p = PROVIDERS[pk]
        print(f"  {i}. {p['label']} (model: {p['default_model']})")
    print(f"  {demo_option}. Demo mode (free, {DEMO_MAX_PER_DAY} requests/day, powered by OpenRouter)")

    while True:
        choice = input(f"Choose [1-{demo_option}] (default 1): ").strip()
        if not choice:
            choice = "1"
        try:
            idx = int(choice)
            if 1 <= idx < demo_option:
                provider = provider_keys[idx - 1]
                break
            if idx == demo_option:
                # Demo mode: use built-in key
                config = {
                    "provider": DEMO_PROVIDER,
                    "key_source": "demo",
                    "api_url": PROVIDERS[DEMO_PROVIDER]["default_url"],
                    "model": PROVIDERS[DEMO_PROVIDER]["default_model"],
                    "demo_usage_today": 0,
                    "demo_usage_date": "",
                }
                save_config(config)
                print(f"Demo mode enabled — {DEMO_MAX_PER_DAY} free requests/day via OpenRouter.")
                print(f"Run `termi --setup` later to switch to your own API key.")
                return config
        except ValueError:
            pass
        print(f"Please enter a number between 1 and {demo_option}.")

    provider_info = PROVIDERS[provider]
    env_key_name = provider_info["env_key"]

    prebuilt_key = os.environ.get("TERMI_PREBUILT_API_KEY") or os.environ.get(
        f"TERMI_PREBUILT_{provider.upper()}_KEY"
    )

    print(f"\nYou selected {provider_info['label']}.")
    use_prebuilt = False
    if prebuilt_key:
        use_prebuilt = ask_confirmation(f"Use the prebuilt {provider_info['label']} key?")
    else:
        print(f"If you have a key set in {env_key_name}, it will be used automatically.")

    if use_prebuilt:
        config = {
            "provider": provider,
            "key_source": "prebuilt",
            "api_url": provider_info["default_url"],
            "model": provider_info["default_model"],
        }
        save_config(config)
        print(f"Saved config to {CONFIG_PATH}")
        return config

    # Prompt for API key with auto-detection
    while True:
        custom_key = input(f"Enter your {provider_info['label']} API key (or paste it): ").strip()
        if custom_key:
            break
        print("API key cannot be empty.")

    # Auto-detect provider from key prefix
    detected_provider = provider
    for prefix, pname in KEY_PREFIX_MAP.items():
        if custom_key.startswith(prefix) and pname != provider:
            detected = ask_confirmation(
                f"Key starts with '{prefix}...' which looks like a {PROVIDERS[pname]['label']} key. "
                f"Switch to {PROVIDERS[pname]['label']}?"
            )
            if detected:
                detected_provider = pname
                provider_info = PROVIDERS[detected_provider]
                break

    config = {
        "provider": detected_provider,
        "key_source": "custom",
        "custom_api_key": custom_key,
        "api_url": provider_info["default_url"],
        "model": provider_info["default_model"],
    }
    save_config(config)
    print(f"Saved config to {CONFIG_PATH}")
    return config


def resolve_api_key(cli_key: str, config: dict[str, Any]) -> str:
    if cli_key:
        return cli_key

    provider = str(config.get("provider", "")).lower()
    provider_info = PROVIDERS.get(provider, PROVIDERS["openai"])

    # Check environment variable for this provider
    env_key = os.environ.get(provider_info["env_key"])
    if not env_key and provider == "google":
        env_key = os.environ.get("GOOGLE_API_KEY")
    if env_key:
        return env_key

    # Also check generic AI_API_KEY
    env_key = os.environ.get("AI_API_KEY")
    if env_key:
        return env_key

    key_source = str(config.get("key_source", "")).lower()
    if key_source == "custom":
        return str(config.get("custom_api_key", "")).strip()
    if key_source == "prebuilt":
        prebuilt_env = f"TERMI_PREBUILT_{provider.upper()}_KEY"
        return os.environ.get(prebuilt_env) or os.environ.get("TERMI_PREBUILT_API_KEY") or ""
    return ""


def _demo_usage_date(config: dict[str, Any]) -> str | None:
    return config.get("demo_usage_date")


def _demo_usage_count(config: dict[str, Any]) -> int:
    return int(config.get("demo_usage_today", 0))


def _demo_remaining_today(config: dict[str, Any]) -> int:
    today = datetime.date.today().isoformat()
    stored = _demo_usage_date(config)
    if stored != today:
        return DEMO_MAX_PER_DAY
    used = _demo_usage_count(config)
    return max(0, DEMO_MAX_PER_DAY - used)


def _demo_used_today(config: dict[str, Any]) -> int:
    today = datetime.date.today().isoformat()
    stored = _demo_usage_date(config)
    if stored != today:
        return 0
    return _demo_usage_count(config)


def _increment_demo_usage(config: dict[str, Any]) -> None:
    today = datetime.date.today().isoformat()
    stored = _demo_usage_date(config)
    if stored != today:
        count = 1
    else:
        count = _demo_usage_count(config) + 1
    config["demo_usage_date"] = today
    config["demo_usage_today"] = count
    save_config(config)


def fallback_generator(instruction: str) -> ModelSuggestion:
    """Local fallback when the AI API is unavailable.
    Matches natural language patterns to safe terminal commands.
    """
    orig = instruction
    instruction = instruction.lower()

    # ———————————————————————————— PWD ————————————————————————————
    if any(w in instruction for w in ["current directory", "working directory",
                                        "where am i", "pwd", "cwd", "print working"]):
        return ModelSuggestion(command="pwd",
            explanation="Print current working directory.",
            risk_level="low", warnings=[], alternatives=["echo $PWD"])

    # —————————————————————— disk / space / usage ——————————————————————
    if any(w in instruction for w in ["disk", "space", "storage", "usage", "size"]):
        m = re.search(r"(?:of|for)\s+(\S+)", instruction)
        if m:
            target = m.group(1)
            return ModelSuggestion(command=f"du -sh {shlex.quote(target)}",
                explanation=f"Show disk usage of '{target}'.",
                risk_level="low", warnings=[], alternatives=["du -sh *"])
        else:
            return ModelSuggestion(command="df -h",
                explanation="Show disk space usage of all mounted filesystems.",
                risk_level="low", warnings=[], alternatives=["du -sh *", "ncdu"])

    # ———————————————————————— date / time ——————————————————————————
    if any(w in instruction for w in ["date", "time", "clock", "today"]):
        return ModelSuggestion(command="date",
            explanation="Show current date and time.",
            risk_level="low", warnings=[], alternatives=["date -u", "cal"])

    # ———————————————————— processes ————————————————————
    if any(w in instruction for w in ["process", "running", "ps", "top", "htop"]):
        cmd = "ps aux" if "all" in instruction else "ps"
        return ModelSuggestion(command=cmd,
            explanation="List running processes.",
            risk_level="low", warnings=[], alternatives=["top", "htop"])

    # ————————————————————— network —————————————————————
    if "ip" in instruction.split() or "address" in instruction or "addresses" in instruction:
        cmd = "ip addr" if platform.system() != "Darwin" else "ifconfig"
        return ModelSuggestion(command=cmd,
            explanation="Show network interfaces.",
            risk_level="low", warnings=[], alternatives=["curl ifconfig.me"])
    if any(w in instruction for w in ["network", "ping", "connectivity"]):
        m = re.search(r"ping\s+(?:to|for|the|a|an)\s+(\S+)", instruction)
        if not m:
            m = re.search(r"ping\s+(\S+)", instruction)
        target = m.group(1) if m else "8.8.8.8"
        return ModelSuggestion(command=f"ping -c 4 {shlex.quote(target)}",
            explanation=f"Ping {target} to check connectivity.",
            risk_level="low", warnings=[], alternatives=["curl -I https://example.com"])

    # ————————————————————— create directory —————————————————————
    m = re.search(r"(?:create|make|new)\s+(?:a\s+)?(?:dir(?:ectory)?|folder)\s+(?:called|named)?\s*(\S+)", instruction)
    if m:
        folder = m.group(1)
        return ModelSuggestion(command=f"mkdir -p {shlex.quote(folder)}",
            explanation=f"Create directory '{folder}'.",
            risk_level="low", warnings=[], alternatives=[])

    # ————————————————————— create file —————————————————————
    m = re.search(r"(?:create|make|new)\s+(?:a\s+)?file\s+(?:called|named)?\s*(\S+)", instruction)
    if m:
        fname = m.group(1)
        return ModelSuggestion(command=f"touch {shlex.quote(fname)}",
            explanation=f"Create empty file '{fname}'.",
            risk_level="low", warnings=[], alternatives=[])

    # ————————————————————— delete / remove —————————————————————
    # 1) "delete all txt files" or "delete all .txt files" → rm *.txt
    m = re.search(r"(?:delete|remove)\s+(?:all\s+)?\.?(\w+)\s+files?", instruction)
    if m:
        ext = m.group(1)
        # "all txt files" → ext = "txt"
        if ext not in ("the", "a", "an", "these", "those", "my"):
            return ModelSuggestion(command=f"rm -v *.{ext}",
                explanation=f"Delete all *.{ext} files.",
                risk_level="high",
                warnings=[f"This will delete all *.{ext} files in the current directory."],
                alternatives=[f"ls *.{ext} to preview first"])
    # 2) "delete temp.txt" (filename with dot)
    for prefix in ["delete", "remove", "trash", "erase", "del"]:
        m = re.search(rf"\b{re.escape(prefix)}\s+([\w.-]+)", instruction)
        if m:
            target = m.group(1)
            if "." in target:
                return ModelSuggestion(command=f"rm {shlex.quote(target)}",
                    explanation=f"Delete file '{target}'.",
                    risk_level="medium",
                    warnings=["Verify the file path before deletion."],
                    alternatives=[])
    # 3) "delete the folder mydata"
    m = re.search(r"(?:delete|remove)\s+(?:the\s+)?(?:file|folder|dir|directory)\s+(\S+)", instruction)
    if m:
        target = m.group(1)
        return ModelSuggestion(command=f"rm -r {shlex.quote(target)}",
            explanation=f"Remove '{target}'.",
            risk_level="medium",
            warnings=["Fallback uses rm; verify paths are correct."],
            alternatives=[])

    # ————————————————————— copy —————————————————————
    m = re.search(r"(?:copy|cp)\s+(\S+)\s+(?:to|into)\s+(\S+)", instruction)
    if m:
        src, dst = m.group(1), m.group(2)
        return ModelSuggestion(command=f"cp {shlex.quote(src)} {shlex.quote(dst)}",
            explanation=f"Copy '{src}' to '{dst}'.",
            risk_level="medium",
            warnings=["Confirm the destination path."],
            alternatives=[f"cp -r {shlex.quote(src)} {shlex.quote(dst)} (for directories)"])

    # ————————————————————— move / rename —————————————————————
    m = re.search(r"(?:move|mv|rename)\s+(\S+)\s+(?:to|into)\s+(\S+)", instruction)
    if m:
        src, dst = m.group(1), m.group(2)
        return ModelSuggestion(command=f"mv {shlex.quote(src)} {shlex.quote(dst)}",
            explanation=f"Move/rename '{src}' to '{dst}'.",
            risk_level="medium",
            warnings=["Moving can overwrite existing files."],
            alternatives=[])

    # ————————————————————— show file contents —————————————————————
    # Only match when there's a clear filename or "contents of" phrase
    show_words = {"show", "display", "print", "cat", "read", "view", "open"}
    if any(w in instruction.split() for w in show_words):
        # "contents of X" or "inside X"
        m = re.search(r"(?:contents?|inside)\s+(?:of\s+)?(.+)$", instruction)
        if m:
            target = m.group(1).rstrip(".,;:!?")
        else:
            # "cat X" / "read X" / "open X" where X has a filename dot
            m = re.search(r"(?:cat|read|view|open)\s+(?:file\s+)?([\w./-]+\.[\w./-]+)", instruction)
            if m:
                target = m.group(1)
            else:
                # "show|print|display [optional words] <file.ext>"
                m = re.search(r"(?:show|display|print)\s+(?:\w+\s+)*(?:file\s+)?([\w./-]+\.[\w./-]+)", instruction)
                if m:
                    target = m.group(1)
                else:
                    target = None
        if target and target.lower() not in ("me", "the", "a", "an", "this", "that",
                                              "all", "file", "files", "folder", "dir",
                                              "directory", ".", "..", "content", "contents"):
            return ModelSuggestion(command=f"cat {shlex.quote(target)}",
                explanation=f"Display contents of '{target}'.",
                risk_level="low", warnings=[], alternatives=["less", "head", "tail"])

    # ————————————————————— list / show directory —————————————————————
    if any(w in instruction.split() for w in ["list", "what's", "ls", "dir"]) or \
       (instruction.startswith("show") and not any(w in instruction for w in
                                                   ["content", "inside", "running", "process",
                                                    "date", "time", "disk", "space", "ip"])):
        if "all" in instruction or "hidden" in instruction:
            return ModelSuggestion(command="ls -la",
                explanation="List all files including hidden ones.",
                risk_level="low", warnings=[], alternatives=["ls -la", "ls -lh"])
        elif "long" in instruction or "detailed" in instruction:
            return ModelSuggestion(command="ls -l",
                explanation="List files with detailed info.",
                risk_level="low", warnings=[], alternatives=["ls -la", "ls -lh"])
        else:
            return ModelSuggestion(command="ls",
                explanation="List files in the current directory.",
                risk_level="low", warnings=[], alternatives=["ls -la", "ls -lh"])

    # ————————————————————— search in file —————————————————————
    if any(w in instruction for w in ["search", "grep"]):
        m = re.search(r"(?:search|grep)\s+(?:for\s+)?['\"]?(.+?)['\"]?\s+in\s+(\S+)", instruction)
        if m:
            pattern, target = m.group(1), m.group(2)
            # Preserve original case from un‑lowered instruction
            m_orig = re.search(r"(?:search|grep)\s+(?:for\s+)?['\"]?(.+?)['\"]?\s+in\s+\S+", orig, re.IGNORECASE)
            if m_orig:
                pattern = m_orig.group(1)
            return ModelSuggestion(command=f"grep -n {shlex.quote(pattern)} {shlex.quote(target)}",
                explanation=f"Search for '{pattern}' in '{target}'.",
                risk_level="low", warnings=[], alternatives=["rg", "ack"])

    # ————————————————————— find files —————————————————————
    if "find" in instruction:
        m = re.search(r"find\s+(?:files?\s+)?(?:named\s+)?['\"]?(.+?)['\"]?\s*$", instruction)
        if m:
            pattern = m.group(1)
            return ModelSuggestion(command=f"find . -name {shlex.quote(pattern)}",
                explanation=f"Find files named '{pattern}'.",
                risk_level="low", warnings=[], alternatives=["locate", "fd"])

    # ————————————————————— default fallback —————————————————————
    return ModelSuggestion(
        command="echo 'fallback: no command generated'",
        explanation="Could not understand the instruction.",
        risk_level="low",
        warnings=[],
        alternatives=[]
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate, validate, preview, and optionally execute safe terminal commands."
    )
    parser.add_argument(
        "instruction",
        nargs="*",
        help="Natural language instruction to convert into a command",
    )
    parser.add_argument("--cwd", default=None, help="Override working directory context")
    parser.add_argument("--os", dest="os_name", default=None, help="Override operating system context")
    parser.add_argument("--shell", default=None, help="Override shell context")
    parser.add_argument("--execute", action="store_true", help="Execute command after validation")
    parser.add_argument("--dry-run", action="store_true", help="Show dry-run preview")
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Auto-confirm high-risk actions that require confirmation",
    )
    parser.add_argument(
        "--allow-critical",
        action="store_true",
        help="Allow critical-risk commands (still requires confirmation unless --yes)",
    )
    parser.add_argument(
        "--allow-shell-features",
        action="store_true",
        help="Allow operators like pipes and redirection during execution",
    )
    parser.add_argument(
        "--api-url",
        default=os.environ.get("AI_API_URL", ""),
        help="Model API URL",
    )
    parser.add_argument(
        "--api-key",
        default=os.environ.get("AI_API_KEY", ""),
        help="Model API key (or set AI_API_KEY)",
    )
    parser.add_argument(
        "--model",
        default=os.environ.get("AI_MODEL", ""),
        help="Model name",
    )
    parser.add_argument(
        "--setup",
        action="store_true",
        help="Run or re-run first-time key setup",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Skip API call and use local fallback generator",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=45,
        help="API request timeout in seconds",
    )
    parser.add_argument(
        "--exec-timeout",
        type=int,
        default=120,
        help="Execution timeout in seconds",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Only print the command (omit explanation and metadata)",
    )
    parser.add_argument(
        "--clip",
        action="store_true",
        help="Copy the suggested command to clipboard instead of printing",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print normalized JSON output instead of human-readable report",
    )
    parser.add_argument(
        "--demo-status",
        action="store_true",
        help="Show remaining demo requests for today",
    )

    args = parser.parse_args()
    instruction_text = " ".join(args.instruction).strip()

    config = run_first_time_setup(force=args.setup)

    if args.setup and not instruction_text:
        print(f"Setup complete. Config saved at {CONFIG_PATH}")
        return 0

    if args.demo_status:
        if str(config.get("key_source", "")).lower() == "demo":
            remaining = _demo_remaining_today(config)
            used = _demo_used_today(config)
            print(f"Demo mode: {used} used, {remaining} remaining today (resets daily)")
        else:
            print(
                f"Demo mode is not enabled. Run `termi --setup` and choose demo mode, "
                f"or configure your own API key.",
            )
        return 0

    api_key = resolve_api_key(args.api_key, config)
    provider = str(config.get("provider", "")).lower() or "openai"

    # Auto‑detect provider from API key prefix if config doesn't match
    if api_key:
        for prefix, pname in KEY_PREFIX_MAP.items():
            if api_key.startswith(prefix) and pname != provider:
                provider = pname
                break

    provider_info = PROVIDERS.get(provider, PROVIDERS["openai"])
    api_url = args.api_url or str(config.get("api_url", "")).strip() or provider_info["default_url"]
    model = args.model or str(config.get("model", "")).strip() or provider_info["default_model"]

    if not instruction_text:
        print("Error: provide a natural language instruction.", file=sys.stderr)
        return 2

    if not args.offline and not api_key:
        if str(config.get("key_source", "")).lower() == "demo":
            remaining = _demo_remaining_today(config)
            if remaining <= 0:
                print(
                    f"Demo limit reached ({DEMO_MAX_PER_DAY}/{DEMO_MAX_PER_DAY} used today). "
                    f"Run `termi --setup` to configure your own API key.",
                    file=sys.stderr,
                )
                return 2
            api_key = BUILTIN_DEMO_KEY
            provider = DEMO_PROVIDER
            provider_info = PROVIDERS[DEMO_PROVIDER]
            api_url = args.api_url or str(config.get("api_url", "")).strip() or provider_info["default_url"]
            model = args.model or str(config.get("model", "")).strip() or provider_info["default_model"]
            print(
                f"[Demo mode] {remaining} free request(s) remaining today.",
                file=sys.stderr,
            )
        else:
            print(
                f"Error: missing API key. Run `termi --setup` or set the {provider_info['env_key']} environment variable.",
                file=sys.stderr,
            )
            return 2

    context = gather_context(args.cwd, args.os_name, args.shell)

    if args.offline:
        suggestion = fallback_generator(instruction_text)
        print("[Offline mode] Using local fallback generator.", file=sys.stderr)
    else:
        try:
            suggestion = call_model(
                api_url=api_url,
                api_key=api_key,
                model=model,
                instruction=instruction_text,
                context=context,
                timeout=args.timeout,
            )
            if api_key == BUILTIN_DEMO_KEY:
                _increment_demo_usage(config)
        except Exception as exc:  # noqa: BLE001
            print(f"Warning: API call failed ({exc}), using local fallback.", file=sys.stderr)
            suggestion = fallback_generator(instruction_text)

    # Validate the suggested command before any reporting
    validation = evaluate_command(suggestion.command, suggestion.risk_level)

    # Determine the output command string (used for quiet, clip, and dry-run)
    command_text = suggestion.command

    if args.quiet:
        print(command_text)
    elif args.json:
        payload = {
            "instruction": instruction_text,
            "environment": {
                "cwd": context.cwd,
                "operating_system": context.operating_system,
                "shell": context.shell,
            },
            "proposal": {
                "command": suggestion.command,
                "explanation": suggestion.explanation,
                "risk_level": suggestion.risk_level,
                "warnings": suggestion.warnings,
                "alternatives": suggestion.alternatives,
            },
            "validation": {
                "risk_level": validation.risk_level,
                "warnings": validation.warnings,
                "requires_confirmation": validation.requires_confirmation,
                "blocked": validation.blocked,
                "hits": [
                    {
                        "rule_id": h.rule_id,
                        "severity": h.severity,
                        "message": h.message,
                        "requires_confirmation": h.requires_confirmation,
                        "block_by_default": h.block_by_default,
                    }
                    for h in validation.hits
                ],
            },
        }
        print(json.dumps(payload, indent=2))
    else:
        print(format_report(instruction_text, context, suggestion, validation))

    if args.clip and command_text:
        _copy_to_clipboard(command_text)

    if args.dry_run:
        print("\n=== Dry Run ===")
        print(build_dry_run_preview(suggestion.command, context.cwd))

    if not args.execute:
        return 0

    if validation.blocked and not args.allow_critical:
        print(
            "\nExecution blocked: command triggered critical safety rules. "
            "Use --allow-critical only after careful review.",
            file=sys.stderr,
        )
        return 3

    needs_confirmation = validation.requires_confirmation or validation.risk_level in {"high", "critical"}
    if needs_confirmation and not args.yes:
        accepted = ask_confirmation(
            f"Command risk is {validation.risk_level}. Proceed with execution?"
        )
        if not accepted:
            print("Execution cancelled.")
            return 0

    try:
        result = execute_command(
            suggestion.command,
            context=context,
            allow_shell_features=args.allow_shell_features,
            timeout=args.exec_timeout,
        )
    except subprocess.TimeoutExpired as exc:
        print(
            f"Execution failed: command exceeded timeout of {args.exec_timeout}s.",
            file=sys.stderr,
        )
        if exc.stdout:
            print("--- partial stdout ---")
            print(exc.stdout.rstrip())
        if exc.stderr:
            print("--- partial stderr ---")
            print(exc.stderr.rstrip())
        return 124
    except Exception as exc:  # noqa: BLE001
        print(f"Execution failed: {exc}", file=sys.stderr)
        return 4

    print("\n=== Execution Result ===")
    print(f"Exit code: {result.returncode}")
    if result.stdout:
        print("--- stdout ---")
        print(result.stdout.rstrip())
    if result.stderr:
        print("--- stderr ---")
        print(result.stderr.rstrip())

    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
