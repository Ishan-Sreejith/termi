# termi

Turn natural language into safe terminal commands.

```bash
pip install termi
termi "list all pdf files"
```

### Quick start

```bash
# First-time setup (pick a provider or use the free built-in demo key)
termi --setup

# Try it out
termi --dry-run "show disk usage"
termi --execute "list files modified today"

# Flags
termi --offline "find large files"         # rule-based, no API
termi "compress this folder" --dry-run     # preview without running
termi "show all processes" --json          # structured output
termi "find .git folders" --quiet          # command only
termi "get my ip" --clip                   # copy to clipboard
```

### Demo mode

A built-in OpenRouter key is available for testing — 10 free requests/day.
Run `termi --setup` and choose **Demo mode**.

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
