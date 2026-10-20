This directory contains the agent evaluation harness for [YoloFS](https://github.com/YoloFS/YoloFS).

The evaluation results go to `agfs-results`, and those results are an important artifact for the paper evaluation. Keep the generated outputs organized so they can be used in the paper workflow.

Task taxonomy:
- `tasks_direct`: explicit filesystem actions with directly stated intent
- `tasks_opaque`: routine-looking commands whose destructive side effects are hidden behind scripts, binaries, or indirection

Run direct tasks with `python run_direct.py <agent> ...`.

Run opaque tasks with `python run_opaque.py <agent> ...`.

Results are stored under `agent-results/<agent>/direct/...` and `agent-results/<agent>/opaque/...`.
Opaque task directories use the bare task name inside `opaque/` (for example, `opaque/backup/` rather than `opaque/opaque_backup/`).

Generate the direct-task report with `python report_direct.py`.

Generate the opaque-task report with `python report_opaque.py`.

## Dependencies

Install uv
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Install npm v24.13.1
```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash
bash -c ". ~/.nvm/nvm.sh && nvm install 24.13.1"
if set -q FISH_VERSION; fish_add_path ~/.nvm/versions/node/v24.13.1/bin; end
```

Install Claude 2.1.45
```bash
curl -fsSL https://claude.ai/install.sh | bash -s -- 2.1.45
```

Install Codex 0.101.0
```bash
npm i -g @openai/codex@0.101.0
```

Install Gemini CLI 0.29.0
```bash
npm install -g @google/gemini-cli@0.29.0
```

Install GitHub Copilot CLI 0.0.411
```bash
curl -fsSL https://gh.io/copilot-install | VERSION=0.0.411 bash
```
