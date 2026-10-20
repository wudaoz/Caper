#!/bin/sh
# YoloFS-Ext (102 dangerous tasks + 102 safe twins) with Claude Code as the agent harness.
# usage (from the repository root): sh claude_code/run_yolofs_ext.sh <hook|auto|yolo> [workers]
#   hook - Caper as a PreToolUse hook (Caper runtime; twins in the same arm)
#   auto - Claude Code Auto Mode;  yolo - YoloFS in Claude Code (both on the bare runtime, twins included)
CC=$1; W=${2:-8}
if [ "$CC" = hook ]; then ARMS=caper; TWINS=; else ARMS=bare; TWINS=1; fi
CC_ARM=$CC YOLOFS_ARMS=$ARMS YOLOFS_BARE_TWINS=$TWINS YOLOFS_PROTOCOL=claude_code/protocol.py \
  YOLOFS_TAG=claude-code-$CC YOLOFS_WORKERS=$W python -m yolofs_ext.runner run
