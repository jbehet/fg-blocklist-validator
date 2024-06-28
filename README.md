# IP-Blocklist-Validator

## Description
This script is designed to manage IP blocklists by automating the tasks listed under Features.
It's specifically tailored to work best with FortiGate Firewalls running FortiOS 7.2.x or later; other firewalls may work as well.

## Features
1. **Repository Initialization**: Initializes the Git repository that stores the input and output files.
2. **Remote Changes Detection**: Checks for changes in the remote Git repository and pulls the latest updates if any are found.
3. **Input File Processing**: Processes input files containing IP addresses by:
   - Removing duplicates.
   - Validating IP addresses.
   - Comparing input and output files to detect changes.
   - Grouping IPs into subnets if a specified threshold is met.
   - Sorting the subnets in CIDR notation from largest to smallest.
4. **Whois Information Retrieval**: Fetches Whois information for newly added addresses to add comments containing country, region and isp.
5. **Output File Management**: Writes the processed IP addresses and their corresponding Whois information to an output file, ensuring various FortiGate limitations are not exceeded.
6. **Git Commit and Push**: Commits and pushes changes to the remote repository if there are any updates.

The script runs at a scheduled interval to ensure the generated blocklists are kept up-to-date. 
Logging is implemented to track the script's operations, and debug mode is available for testing without requiring remote repository changes to run and without pushing the generated changes.

## Usage
1. **Clone the Repository**: Clone the repository to your local machine.
2. **Set Parameters**: Modify the parameters in the script as needed, such as `REPO_PATH`, `INPUT_FILES_TO_PROCESS`, and `RUN_SCRIPT_INTERVAL_HOURS`.
3. **Run the Script**: Execute the script to start processing the blocklists and scheduling the task.
4. **Monitor Logs**: Check the log file (`blocklist_processor.log`) for detailed logs of the script's operations.

## Requirements
- Python 3.x
- `gitpython` for Git operations
- `requests` for fetching Whois information
- `schedule` for scheduling tasks

Install the necessary packages using:
```bash
pip install gitpython requests schedule
```

## Disclaimer
- This tool is intended for internal use only.
- Unauthorized access, distribution, or use by external parties is prohibited.
- Provided "as is" without warranties or guarantees.
- We are not liable for any consequences resulting from its use or misuse.
