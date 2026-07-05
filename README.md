# termi

Turn natural language into safe terminal commands.

```bash
pip install termi
termi "list all pdf files"
```

### Quick start

```bash
# Runs offline by default (no internet needed)
termi --dry-run "show disk usage"
termi --execute "list files modified today"

# Use AI (requires API key or demo mode)
termi --setup
termi --online "compress this folder" --dry-run

# Flags
termi --online "find large files" --dry-run  # AI-powered
termi "show all processes" --json            # structured output (offline)
termi "find .git folders" --quiet            # command only
termi "get my ip" --clip                     # copy to clipboard
```

### Offline vs online

- **Default (offline)** — no internet, no API key needed. Rule-based matching (36+ patterns)
- `--online` — uses AI API (OpenAI / OpenRouter / Gemini). Requires key or demo mode.

### Demo mode

A built-in OpenRouter key is available for testing — 10 free requests/day.
Run `termi --setup` and choose **Demo mode**, then use `--online`.

### Providers

- OpenAI (`sk-...`)
- OpenRouter (`sk-or-...`)
- Google Gemini (`AIza...`)

API keys can be entered via setup, set as `OPENAI_API_KEY` / `OPENROUTER_API_KEY` / `GOOGLE_API_KEY`, or passed with `--api-key`.

### Install from source

```bash
git clone https://github.com/Ishan-Sreejith/termi
cd termi
pip install .
```
