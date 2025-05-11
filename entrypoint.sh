#!/bin/bash

set -e

CLONE_DIR="/app/repo"
CLONE_URL="https://${GIT_USERNAME}:${GIT_TOKEN}@${GIT_REPO_URL#https://}"

echo "Preparing repo directory at $CLONE_DIR..."

if [ -d "$CLONE_DIR/.git" ]; then
  echo "Git repository already exists. Verifying remote URL..."

  cd "$CLONE_DIR"
  EXISTING_URL=$(git config --get remote.origin.url)

  if [ "$EXISTING_URL" == "$CLONE_URL" ]; then
    echo "Remote already exists and matches expected repository."
  else
    echo "Remote mismatch! Expected $CLONE_URL but found $EXISTING_URL"
    echo "Please delete $CLONE_DIR manually or rebuild the container."
    exit 1
  fi
else
  echo "Cloning repo from $GIT_REPO_URL..."
  git clone --branch "$GIT_BRANCH" "$CLONE_URL" "$CLONE_DIR"
  cd "$CLONE_DIR"
fi

cd /app

echo "Starting application..."
python /app/main.py
