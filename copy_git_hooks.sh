#!/bin/bash
# Copy git hooks from the .git_hooks folder to .git/hooks
# This will overwrite any hooks that already exist
echo "Installing .git_hooks to .git/hooks"
cp -f .git_hooks/* .git/hooks/

