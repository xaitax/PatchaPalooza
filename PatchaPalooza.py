import requests
import argparse
import termcolor
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from bs4 import BeautifulSoup
import json

BASE_URL = "https://api.msrc.microsoft.com/cvrf/v2.0/"
HEADERS = {"Accept": "application/json"}
DATA_DIR = Path("msrc_data")
CVSS_THRESHOLD = 8.0


def load_json_data(file_path: Path) -> dict:
    try:
        with file_path.open("r") as file:
            return json.load(file)
    except FileNotFoundError as e:
        print(f"File not found: {file_path} - {e}")
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from {file_path} - {e}")


def ensure_directory_exists(directory: Path):
    directory.mkdir(parents=True, exist_ok=True)


def retrieve_all_summaries():
    endpoint = f"{BASE_URL}updates"
    try:
        response = requests.get(endpoint, headers=HEADERS)
        response.raise_for_status()
    except requests.HTTPError as e:
        print(f"HTTP error occurred: {e.response.status_code} - {e.response.text}")
        return []
    except requests.RequestException as e:
        print(f"An error occurred: {e}")
        return []
    return response.json().get("value", [])


def retrieve_and_store_data():
    ensure_directory_exists(DATA_DIR)
    summaries = retrieve_all_summaries()
    tracked_months = []

    with requests.Session() as session:
        for summary in summaries:
            month_id = summary["ID"]
            file_path = DATA_DIR / f"{month_id}.json"
            if not file_path.exists():
                try:
                    response = session.get(
                        f"{BASE_URL}cvrf/{month_id}", headers=HEADERS
                    )
                    response.raise_for_status()
                    with file_path.open("w") as file:
                        json.dump(response.json(), file)
                    print(termcolor.colored(f"[+] Stored data for {month_id}", "green"))
                except requests.HTTPError as e:
                    print(
                        f"HTTP error occurred for {month_id}: {e.response.status_code} - {e.response.text}"
                    )
                except requests.RequestException as e:
                    print(
                        f"An error occurred while retrieving data for {month_id}: {e}"
                    )
            tracked_months.append(month_id)

    all_months = {summary["ID"] for summary in summaries}
    missing_months = all_months - set(tracked_months)
    if not missing_months:
        print(termcolor.colored("[+] Data fully updated.", "green"))
    else:
        print(
            termcolor.colored(
                f"[-] Missing data for months: {', '.join(missing_months)}", "red"
            )
        )

    last_update_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(termcolor.colored(f"[i] Last updated: {last_update_time}", "blue"))


def extract_severity_and_exploitation(vuln):
    severity = "Unknown"
    exploited_status = "Not Exploited"
    for threat in vuln.get("Threats", []):
        description = threat.get("Description", {}).get("Value", "")
        if "Exploited:Yes" in description:
            exploited_status = "Exploited"
        if "Severity:" in description:
            severity = description.split("Severity:")[1].split()[0]
    return severity, exploited_status


def get_cvss_score(vuln):
    cvss_sets = vuln.get("CVSSScoreSets")
    if cvss_sets:
        return cvss_sets[0].get("BaseScore")
    return "N/A"


def display_cve_details(cve_id):
    found = False
    for file_path in DATA_DIR.glob("*.json"):
        data = load_json_data(file_path)
        vulnerabilities = data.get("Vulnerability", [])
        for vuln in vulnerabilities:
            if vuln.get("CVE", "") == cve_id:
                found = True

                print(termcolor.colored(f"\nDetails for {cve_id}:", "blue"))
                print("-" * (len(cve_id) + 14))

                print(f"{'Title:':<20} {vuln.get('Title', {}).get('Value', 'N/A')}")
                cvss_sets = vuln.get("CVSSScoreSets", [{}])[0]
                print(f"{'CVSS:':<20} {cvss_sets.get('BaseScore', 'N/A')}")
                print(f"{'Vector:':<20} {cvss_sets.get('Vector', 'N/A')}")

                severity, exploited_status = extract_severity_and_exploitation(vuln)
                exploited_color = "red" if exploited_status == "Exploited" else "green"
                print(
                    f"{'Status:':<20} {termcolor.colored(exploited_status, exploited_color)}"
                )

                threat_descriptions = set(
                    [
                        threat.get("Description", {}).get("Value", "N/A")
                        for threat in vuln.get("Threats", [])
                    ]
                )
                print(f"{'Threat:':<20} {', '.join(threat_descriptions)}")

                notes = [
                    note.get("Value", "")
                    for note in vuln.get("Notes", [])
                    if note.get("Type") == 1
                ]
                for note in notes:
                    clean_note = BeautifulSoup(note, "html.parser").get_text()
                    print(f"{'Description:':<20} {clean_note}")

                remediations = vuln.get("Remediations", [])
                for rem in remediations:
                    if rem.get("URL"):
                        print(f"{'Remediation URL:':<20} {rem.get('URL', 'N/A')}")
                        break

                acknowledgments = ", ".join(
                    [
                        ack_dict.get("Value", "")
                        for ack in vuln.get("Acknowledgments", [])
                        for ack_dict in ack.get("Name", [])
                    ]
                )
                print(f"{'Acknowledgments:':<20} {acknowledgments}")

                references = [
                    ref.get("URL", "N/A") for ref in vuln.get("References", [])
                ]
                if references:
                    print("\nReferences:")
                    for ref in references:
                        print(f"    - {ref}")
                break
        if found:
            break
    if not found:
        print(f"No details found for {cve_id}.")


def analyze_and_display_month_data(month):
    file_path = DATA_DIR / f"{month}.json"
    if not file_path.exists():
        print(f"[!] No data found for {month}.")
        return

    data = load_json_data(file_path)
    vulnerabilities = data.get("Vulnerability", [])

    display_statistics(vulnerabilities, month)

    sorted_vulnerabilities = sorted(
        vulnerabilities,
        key=lambda x: (
            extract_severity_and_exploitation(x)[1] == "Exploited",
            0 if get_cvss_score(x) == "N/A" else float(get_cvss_score(x)),
        ),
        reverse=True,
    )

    exploited_vulns = [
        vuln
        for vuln in sorted_vulnerabilities
        if extract_severity_and_exploitation(vuln)[1] == "Exploited"
    ]
    not_exploited_vulns = [
        vuln
        for vuln in sorted_vulnerabilities
        if extract_severity_and_exploitation(vuln)[1] != "Exploited"
    ]

    print(f"Exploited ({len(exploited_vulns)})")
    print("-" * 13)
    for vuln in exploited_vulns:
        cve = vuln.get("CVE", "")
        title = vuln.get("Title", {}).get("Value", "")
        cvss_score = get_cvss_score(vuln)
        print(f"    {cve} - {cvss_score} - {title}")
    print()

    print(f"Not Exploited ({len(not_exploited_vulns)})")
    print("-" * 19)
    for vuln in not_exploited_vulns:
        cve = vuln.get("CVE", "")
        title = vuln.get("Title", {}).get("Value", "")
        cvss_score = get_cvss_score(vuln)
        print(f"    {cve} - {cvss_score} - {title}")


def count_type(search_type, all_vulns):
    counter = 0
    for vuln in all_vulns:
        for threat in vuln.get("Threats", []):
            if threat.get("Type") == 0:
                if search_type == "Edge - Chromium":
                    if threat.get("ProductID", [None])[0] == "11655":
                        counter += 1
                        break
                elif threat.get("Description", {}).get("Value") == search_type:
                    if threat.get("ProductID", [None])[0] == "11655":
                        break
                    counter += 1
                    break
    return counter


def display_statistics(vulnerabilities, month):
    exploitation_status = defaultdict(int)
    category_vulnerabilities = defaultdict(int)

    categories = [
        "Elevation of Privilege",
        "Security Feature Bypass",
        "Remote Code Execution",
        "Information Disclosure",
        "Denial of Service",
        "Spoofing",
        "Edge - Chromium",
    ]

    for vuln in vulnerabilities:
        _, exploited_status = extract_severity_and_exploitation(vuln)
        exploitation_status[exploited_status] += 1

    for category in categories:
        category_vulnerabilities[category] = count_type(category, vulnerabilities)

    cvss_scores = [get_cvss_score(vuln) for vuln in vulnerabilities]
    above_threshold = len(
        [
            score
            for score in cvss_scores
            if score != "N/A" and float(score) >= CVSS_THRESHOLD
        ]
    )

    print(
        termcolor.colored(f"[x] Microsoft PatchaPalooza Statistics for {month}", "blue")
    )
    print(
        "\n    "
        + termcolor.colored("Total:", "red")
        + f"\t\t{len(vulnerabilities)} vulnerabilities."
    )
    print(
        "    "
        + termcolor.colored("Exploited:", "red")
        + f"\t\t{exploitation_status['Exploited']} vulnerabilities."
    )
    print(
        "    "
        + termcolor.colored("Not Exploited:", "red")
        + f"\t{exploitation_status['Not Exploited']} vulnerabilities."
    )
    print(
        "    "
        + termcolor.colored(f"CVSS (>= {CVSS_THRESHOLD}):", "red")
        + f"\t{above_threshold} vulnerabilities.\n"
    )

    sorted_categories = sorted(
        category_vulnerabilities.items(), key=lambda x: x[1], reverse=True
    )
    for category, count in sorted_categories:
        print(f"    {count} vulnerabilities in {category}.")
    print("\n")


def read_all_data_from_directory():
    all_data = {}
    for file_path in DATA_DIR.glob("*.json"):
        month_id = file_path.stem
        with file_path.open("r") as file:
            all_data[month_id] = json.load(file)
    return all_data


def derive_statistics_from_all_data():
    all_data = read_all_data_from_directory()

    exploited_counts = {}
    high_cvss_counts = {}
    category_counts = defaultdict(int)

    for month, data in all_data.items():
        vulnerabilities = data.get("Vulnerability", [])

        exploited_vulns = [
            vuln
            for vuln in vulnerabilities
            if extract_severity_and_exploitation(vuln)[1] == "Exploited"
        ]
        high_cvss_vulns = [
            vuln
            for vuln in vulnerabilities
            if get_cvss_score(vuln) != "N/A" and float(get_cvss_score(vuln)) >= 8.0
        ]

        exploited_counts[month] = len(exploited_vulns)
        high_cvss_counts[month] = len(high_cvss_vulns)

        for vuln in vulnerabilities:
            for threat in vuln.get("Threats", []):
                if threat.get("Type") == 0:
                    category = threat.get("Description", {}).get("Value")
                    category_counts[category] += 1

    sorted_exploited = sorted(
        exploited_counts.items(), key=lambda x: x[1], reverse=True
    )
    sorted_high_cvss = sorted(
        high_cvss_counts.items(), key=lambda x: x[1], reverse=True
    )
    sorted_categories = sorted(
        category_counts.items(), key=lambda x: x[1], reverse=True
    )

    return sorted_exploited, sorted_high_cvss, sorted_categories


(
    sorted_exploited,
    sorted_high_cvss,
    sorted_categories,
) = derive_statistics_from_all_data()
sorted_exploited, sorted_high_cvss, sorted_categories


def display_overall_statistics(exploited_stats, high_cvss_stats, category_stats):
    print(termcolor.colored("\n[+] Overall Statistics from All Monthly Data", "blue"))
    print("-" * 44)

    print(
        termcolor.colored("\nTop 5 Months with Most Exploited Vulnerabilities:", "red")
    )
    for month, count in exploited_stats[:5]:
        print(f"    {month}: {count} exploited vulnerabilities")

    print(
        termcolor.colored("\nTop 5 Months with Most High CVSS Vulnerabilities:", "red")
    )
    for month, count in high_cvss_stats[:5]:
        print(f"    {month}: {count} vulnerabilities with CVSS >= 8.0")

    print(termcolor.colored("\nVulnerability Categories Across All Months:", "red"))
    for category, count in category_stats:
        print(f"    {category}: {count} vulnerabilities")
    print("\n")


def main():
    parser = argparse.ArgumentParser(description="PatchaPalooza")

    def valid_month(month_str):
        try:
            datetime.strptime(month_str, "%Y-%b")
            return month_str
        except ValueError:
            raise argparse.ArgumentTypeError(
                f"Given Month ({month_str}) not in the correct format. Expected format: YYYY-MMM."
            )

    parser.add_argument(
        "--month",
        help="Specify the month for analysis in format YYYY-MMM. Defaults to current month.",
        default=datetime.now().strftime("%Y-%b"),
        type=valid_month,
    )
    parser.add_argument(
        "--update", help="Retrieve and store latest data.", action="store_true"
    )
    parser.add_argument(
        "--stats", help="Display statistics from all monthly data.", action="store_true"
    )
    parser.add_argument(
        "--detail", help="Provide details for a specific CVE.", default=None, type=str
    )

    args = parser.parse_args()

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    if not args.update and not args.stats and not args.detail:
        banner = r"""
__________         __         .__          __________        .__                               
\______   \_____ _/  |_  ____ |  |__ _____ \______   \_____  |  |   ____   _________________   
 |     ___/\__  \\   __\/ ___\|  |  \\__  \ |     ___/\__  \ |  |  /  _ \ /  _ \___   /\__  \  
 |    |     / __ \|  | \  \___|   Y  \/ __ \|    |     / __ \|  |_(  <_> |  <_> )    /  / __ \_
 |____|    (____  /__|  \___  >___|  (____  /____|    (____  /____/\____/ \____/_____ \(____  /
                \/          \/     \/     \/               \/                        \/     \/ 
        """
        print(banner)
        print("Alexander Hagenah / @xaitax / ah@primepage.de\n\n")
        analyze_and_display_month_data(args.month)
        return

    if args.update:
        retrieve_and_store_data()
        return

    if args.detail:
        display_cve_details(args.detail)
        return

    if args.stats:
        (
            exploited_stats,
            high_cvss_stats,
            category_stats,
        ) = derive_statistics_from_all_data()
        display_overall_statistics(exploited_stats, high_cvss_stats, category_stats)
    else:
        analyze_and_display_month_data(args.month)


if __name__ == "__main__":
    main()
