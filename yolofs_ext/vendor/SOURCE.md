# Vendored YoloFS task fixtures

- Source: https://github.com/YoloFS/agent-eval, commit 0956f8e46b31ead201e6a377f227d0cddd2419d9
- Paper: Zhong et al., "Don't Let AI Agents YOLO Your Files: Information and Control in Agent-Native Filesystems", arXiv:2604.13536.
- Included: `tasks_opaque/` (the 13 hidden-side-effect projects, their requests, protected files and harm annotations), `common.py`, `README.md`, copied unchanged.
- Not included: the direct tasks, the precompiled binaries and their C sources, which YoloFS-Ext does not use; YoloFS-Ext writes and compiles its own tools.
- License: the YoloFS system repository is released under GPL-2.0; the agent-eval repository does not state a license. These files are redistributed for research evaluation; all rights remain with their authors.
