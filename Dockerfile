# Use a Python base image
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install Git
RUN apt-get update && apt-get install -y git && apt-get clean

# Copy code
COPY . /app

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Make entrypoint script executable
RUN chmod +x entrypoint.sh

# Set environment variables (override at runtime!)
ENV GIT_REPO_URL=https://github.com/myuser/myrepo.git
ENV GIT_BRANCH=main
ENV GIT_USERNAME=myuser
ENV GIT_TOKEN=mytoken
ENV DEBUG=false
ENV RUN_SCRIPT_INTERVAL_MINUTES=15
ENV THRESHOLD_GROUP_IPS_INTO_SUBNETS=5

# Run entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]