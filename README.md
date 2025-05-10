# FG-Blocklist-Validator

## Description

This script is designed to manage IP blocklists by automating the tasks listed under Features.
It's specifically tailored to work best with FortiGate Firewalls running FortiOS 7.2.x or later; other firewalls may work as well.

---

## Features

1. **Git Repository Integration**: Automatically pulls, commits, and pushes changes from/to a remote Git repo.
2. **IP Blocklist Processing**:

   * Removes duplicates
   * Validates IP addresses
   * Sorts and groups IPs into subnets (based on a threshold)
3. **Whois Annotation**: Adds metadata (country, region, ISP) for new IPs using whois data.
4. **CIDR Sorting**: Orders output in CIDR notation from largest to smallest.
5. **Scheduled Execution**: Runs periodically using an interval you define (via env variable).
6. **Logging**: Outputs detailed logs to a mounted volume for persistent storage.
7. **Debug Mode**: Allows dry-run execution for testing purposes.

---

## Quick Start

### 1. Clone the Repository / Build the Docker Image

```bash
git clone https://github.com/jbehet/fg-blocklist-validator.git
cd fg-blocklist-validator
docker build -t fg-blocklist-validator .
```

### 2. Run the Container

> Replace `GIT_REPO_URL`, `GIT_USERNAME`, `GIT_TOKEN` and `/path/on/host/log` with your values.

### -> Docker Compose:

```yaml
services:
  fg-blocklist-validator:
    image: fg-blocklist-validator:latest
    container_name: fg-blocklist-validator
    environment:
      - GIT_BRANCH=main
      - GIT_REPO_URL=https://github.com/youruser/yourrepo.git
      - GIT_USERNAME=youruser
      - GIT_TOKEN=yourtoken
      - DEBUG=false
      - RUN_SCRIPT_INTERVAL_MINUTES=15
      - THRESHOLD_GROUP_IPS_INTO_SUBNETS=5
    volumes:
      - /path/on/host/log:/app/log
    security_opt:
      - no-new-privileges:true
    restart: unless-stopped
```


```bash
docker compose up -d
```

### -> Docker Run:
```bash
docker run -d \
  --name fg-blocklist-validator \
  -e GIT_BRANCH=main \
  -e GIT_REPO_URL=https://github.com/youruser/yourrepo.git \
  -e GIT_USERNAME=youruser \
  -e GIT_TOKEN=yourtoken \
  -e DEBUG=false \
  -e RUN_SCRIPT_INTERVAL_MINUTES=15 \
  -e THRESHOLD_GROUP_IPS_INTO_SUBNETS=5 \
  -v /path/on/host/log:/app/log \
  --security-opt no-new-privileges:true \
  --restart unless-stopped \
  fg-blocklist-validator:latest
```

---

## Environment Variables

| Variable                           | Description                      | Required | Example                  |
| ---------------------------------- | -------------------------------- | -------- | ------------------------ |
| `GIT_BRANCH`                       | Branch to monitor and update     | ✅        | `main`                   |
| `GIT_REPO_URL`                     | Git repository URL               | ✅        | `https://github.com/...` |
| `GIT_USERNAME`                     | Git username                     | ✅        | `myuser`                 |
| `GIT_TOKEN`                        | Git token for authentication     | ✅        | `ghp_XXXX...`            |
| `DEBUG`                            | Enables debug mode               | optional | `true` or `false`        |
| `RUN_SCRIPT_INTERVAL_MINUTES`      | Interval between runs in minutes | optional | `15`                      |
| `THRESHOLD_GROUP_IPS_INTO_SUBNETS` | Grouping threshold               | optional | `5`                      |

---

## Manual Python Execution (Optional)

If you prefer running outside Docker:

### Requirements

* Python 3.x
* `gitpython`, `requests`, `schedule`

### Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Run

```bash
python main.py
```

Logs are written to `./log/script.log`

---

## Logs

Logs are stored inside the container at `/app/log/script.log`. When using the reccomended bind mounts, they'll be available on your host at the path you mounted to (e.g., `/home/myuser/fg-blocklist-validator/script.log`).

---

## Disclaimer

* This tool is intended for internal use only.
* Unauthorized access, distribution, or use by external parties is prohibited.
* Provided "as is" without warranties or guarantees.
* We are not liable for any consequences resulting from its use or misuse.
