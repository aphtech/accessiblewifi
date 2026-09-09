#!/bin/bash

ISSUE="$1"

claude \
  --dangerously-skip-permissions \
  --append-system-prompt-file CLAUDE.md \
  "You are fixing a bug in This project

Read the following issue carefully and complete the work from start to finish.

$(cat "$ISSUE")"
