import os
import time
import logging
import ipaddress
from collections import defaultdict
from git import Repo
import requests
import schedule

DEBUG: bool = False
RUN_SCRIPT_INTERVAL_HOURS: int = 2
THRESHOLD_GROUP_IPS_INTO_SUBNET: int = 10
REPO_PATH: str = "E:\\GIT\\Python\\fg_internal_blocklist"
INPUT_FILES_TO_PROCESS: list = [
    "add-manual-addresses-here.txt",
    "add-automated-addresses-here.txt",
]

# Set up logging
logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("blocklist_processor.log"),
        logging.StreamHandler(),
    ],
)


def initialize_repo() -> Repo:
    """Initialize and return a git repository object."""
    try:
        repo = Repo(REPO_PATH)
        logging.info(f"Initialized Git repository at {REPO_PATH}")
        return repo
    except Exception as e:
        logging.error(f"Error initializing Git repository: {e}")
        exit(1)


def check_for_remote_changes(repo: Repo) -> bool:
    """Check if there are remote changes in the repository."""
    origin = repo.remotes.origin
    origin.fetch()
    local_commit = repo.commit("refs/heads/main")
    remote_commit = repo.commit("refs/remotes/origin/main")
    return local_commit != remote_commit


def pull_latest_changes(repo: Repo) -> None:
    """Pull the latest changes from the remote repository."""
    repo.remotes.origin.pull()
    logging.info("Pulled the latest changes from the remote repository.")


def load_input_file(file_path: str) -> list:
    """Load and return the list of addresses from the input file."""
    try:
        with open(file_path, "r") as file:
            lines = [line.strip() for line in file]
            logging.info(f"Loaded {len(lines)} lines from {file_path}")
            return lines
    except FileNotFoundError:
        logging.error(f"Input file {file_path} not found.")
        exit(1)


def load_existing_output_file(file_path: str) -> dict:
    """Load the existing output file and return its entries."""
    entries = {}
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as file:
            for line in file:
                if line.strip() and not line.startswith("#"):
                    parts = line.split(" ", 1)
                    entry = parts[0].strip()
                    comment = parts[1].strip("# ").strip() if len(parts) > 1 else ""
                    entries[entry] = comment
        logging.info(f"Loaded {len(entries)} entries from {file_path}")
    else:
        logging.info(f"No existing output file found at {file_path}")
    return entries


def remove_duplicates(addresses: list) -> list:
    """Remove duplicate addresses and return a sorted list."""
    unique_addresses = sorted(set(addresses))
    logging.info(
        f"Removed duplicates. {len(addresses)} -> {len(unique_addresses)} unique addresses."
    )
    return unique_addresses


def validate_ip_addresses(addresses: list) -> list:
    """Validate IP addresses and filter out invalid ones."""
    valid_ips = []
    for ip in addresses:
        try:
            ipaddress.ip_address(ip.split("/")[0])
            valid_ips.append(ip)
        except ValueError:
            logging.warning(f"ERROR: {ip} is not a valid IP address!")
    logging.info(
        f"Validated addresses. {len(valid_ips)} valid, {int(len(addresses) - len(valid_ips))} invalid."
    )
    return valid_ips


def group_ips_into_subnets(addresses: list) -> list:
    """Group individual IP addresses into subnets if they exceed a threshold."""
    ip_dict = defaultdict(list)
    existing_subnets, individual_ips = set(), set()

    for entry in addresses:
        if "/" not in entry:
            entry += "/32"  # Treat plain IPs as /32 subnets
        network = ipaddress.ip_network(entry, strict=False)
        if network.prefixlen == 32:
            first_three_octets = str(network.network_address).rsplit(".", 1)[0]
            ip_dict[first_three_octets].append(network)
            individual_ips.add(network)
        else:
            existing_subnets.add(network)

    for subnet in existing_subnets:
        first_three_octets = str(subnet.network_address).rsplit(".", 1)[0]
        if first_three_octets in ip_dict:
            del ip_dict[first_three_octets]

    result = set()
    for octets, ips in ip_dict.items():
        if len(ips) >= THRESHOLD_GROUP_IPS_INTO_SUBNET:
            result.add(f"{octets}.0/24")
            individual_ips.difference_update(ips)

    result.update(str(subnet) for subnet in existing_subnets)
    result.update(str(ip) for ip in individual_ips)

    logging.info(f"Grouped into subnets. {len(result)} entries after grouping.")
    return list(result)


def sort_cidr_notation(entries: dict) -> dict:
    """Sort the subnets in CIDR notation from largest to smallest subnets and then the IPs."""

    def sort_key(entry):
        network = ipaddress.ip_network(entry, strict=False)
        return (network.prefixlen, network.network_address)

    sorted_entries = dict(sorted(entries.items(), key=lambda item: sort_key(item[0])))
    logging.info(f"Sorted subnets. {len(sorted_entries)} entries after sorting.")
    return sorted_entries


def fetch_whois_info(entries: list, existing_entries: dict) -> dict:
    """Check Whois information for each entry that is new or changed."""
    whois_info = {}
    logging.info(
        "Start fetching WhoIs information for new or changed entries. This could take a while..."
    )
    for entry in entries:
        if entry not in existing_entries:
            try:
                response = requests.get(
                    f"http://ipwho.is/{entry.split('/')[0]}?fields=country,region,connection.isp"
                )
                response_json = response.json()
                comment = f"{response_json.get('country')} | {response_json.get('region')} | {response_json.get('connection', {}).get('isp')}"
                whois_info[entry] = comment
            except Exception as e:
                logging.error(f"Error processing {entry}: {e}")
        else:
            whois_info[entry] = existing_entries[entry]
    logging.info("WhoIs information processed.")
    return whois_info


def write_entries_to_file(entries: dict, file_path: str) -> bool:
    """Write the processed addresses to the output file and return success."""
    max_entries = 131072
    max_size_bytes = 10485760
    max_comment_len = 63

    if len(entries) >= max_entries:
        logging.error("The number of entries exceeds the limit of 131072")
        return False

    try:
        with open(file_path, "w", encoding="utf-8") as file:
            for entry, comment in entries.items():
                if comment:
                    comment = (
                        f"# {comment[:max_comment_len-5]}...\n"
                        if len(comment) > max_comment_len - 2
                        else f"# {comment}\n"
                    )
                file.write(f"{entry} {comment}" if comment else f"{entry}\n")
        file_size = os.path.getsize(file_path)
        if file_size > max_size_bytes:
            logging.error(
                f"The file size exceeds the limit of {int(max_size_bytes / 1024 / 1024)}MB"
            )
            return False
        else:
            logging.info(f"Output written to {file_path} ({file_size} bytes)")
            return True
    except IOError as e:
        logging.error(f"Error writing to output file: {e}")
        return False


def process_lists(file_path: str, output_file_path: str) -> bool:
    """Process the input file: load, deduplicate, validate, group, and write to output."""
    raw_addresses = load_input_file(file_path)
    unique_addresses = remove_duplicates(raw_addresses)
    valid_addresses = validate_ip_addresses(unique_addresses)
    grouped_addresses = group_ips_into_subnets(valid_addresses)

    existing_entries = load_existing_output_file(output_file_path)
    looked_up_addresses = fetch_whois_info(grouped_addresses, existing_entries)

    # Remove entries that are no longer present in the input file
    current_entries = set(grouped_addresses)
    removed_entries = set(existing_entries) - current_entries
    for entry in removed_entries:
        del existing_entries[entry]

    sorted_entries = sort_cidr_notation({**existing_entries, **looked_up_addresses})
    return write_entries_to_file(sorted_entries, output_file_path)


def commit_and_push(repo: Repo) -> None:
    """Commit and push changes to the remote repository."""
    repo.git.add(update=True)
    if repo.is_dirty(untracked_files=True):
        repo.index.commit("Update validated blocklists")
        repo.remotes.origin.push()
        logging.info("Changes committed and pushed to the remote repository.")
    else:
        logging.info("No changes to commit.")


def main() -> None:
    """Main function to process the input files."""
    repo = initialize_repo()
    if check_for_remote_changes(repo) or DEBUG:
        pull_latest_changes(repo)

        for file_name in INPUT_FILES_TO_PROCESS:
            file_path = os.path.join(REPO_PATH, file_name)
            output_file_path = os.path.join(
                REPO_PATH,
                "output",
                f"blocklist-industrial{'-manual' if 'manual' in file_name else ''}.txt",
            )
            processed = process_lists(file_path, output_file_path)

        if processed and not DEBUG:
            commit_and_push(repo)
        elif processed and DEBUG:
            logging.warning("Currently in debug mode, not pushing to git.")
        else:
            logging.error("Error during output file validation, not pushing to git.")
    else:
        logging.info(
            "No remote changes detected and not in debug mode. Skipping processing."
        )


def schedule_task() -> None:
    """Schedule the main function to run every n hours."""
    main()

    schedule.every(RUN_SCRIPT_INTERVAL_HOURS).hours.do(main)
    logging.info(f"Scheduled task to run again in {RUN_SCRIPT_INTERVAL_HOURS} hours.")

    while True:
        schedule.run_pending()
        time.sleep(1)


if __name__ == "__main__":
    schedule_task()
