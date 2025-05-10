#!/bin/bash

# Exit on any error
set -e

# Clone the repo using token
echo "Cloning repo from $GIT_REPO_URL..."
git clone --branch "$GIT_BRANCH" "https://${GIT_USERNAME}:${GIT_TOKEN}@${GIT_REPO_URL#https://}" /app/repo

# Run the script
echo "Starting application..."
python /app/main.py