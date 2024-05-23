import requests
import argparse
from termcolor import colored
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from bs4 import BeautifulSoup
import json

BASE_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/"
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
    return {}

def ensure_directory_exists(directory: Path):
    directory.mkdir(parents=True, exist_ok=True)

def retrieve_all_summaries():
    endpoint = f"{BASE_URL}updates"
    try:
        response = requests.get(endpoint, headers=HEADERS)
        response.raise_for_status()
        return response.json().get("value", [])
    except requests.HTTPError as e:
        print(f"HTTP error occurred: {e.response.status_code} - {e.response.text}")
    except requests.RequestException as e:
        print(f"An error occurred: {e}")
    return []

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
                    response = session.get(f"{BASE_URL}cvrf/{month_id}", headers=HEADERS)
                    response.raise_for_status()
                    with file_path.open("w") as file:
                        json.dump(response.json(), file)
                    print(colored(f"[+] Stored data for {month_id}", "green"))
                except requests.HTTPError as e:
                    print(f"HTTP error occurred for {month_id}: {e.response.status_code} - {e.response.text}")
                except requests.RequestException as e:
                    print(f"An error occurred while retrieving data for {month_id}: {e}")
            tracked_months.append(month_id)

    all_months = {summary["ID"] for summary in summaries}
    missing_months = all_months - set(tracked_months)
    if not missing_months:
        print(colored("[+] Data fully updated.", "green"))
    else:
        print(colored(f"[-] Missing data for months: {', '.join(missing_months)}", "red"))

    last_update_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(colored(f"[i] Last updated: {last_update_time}", "blue"))

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

                print(colored(f"\nDetails for {cve_id}:", "blue"))
                print("-" * (len(cve_id) + 14))

                print(f"{'Title:':<20} {vuln.get('Title', {}).get('Value', 'N/A')}")
                cvss_sets = vuln.get("CVSSScoreSets", [{}])[0]
                print(f"{'CVSS:':<20} {cvss_sets.get('BaseScore', 'N/A')}")
                print(f"{'Vector:':<20} {cvss_sets.get('Vector', 'N/A')}")

                severity, exploited_status = extract_severity_and_exploitation(vuln)
                exploited_color = "red" if exploited_status == "Exploited" else "green"
                print(f"{'Status:':<20} {colored(exploited_status, exploited_color)}")

                threat_descriptions = {threat.get("Description", {}).get("Value", "N/A") for threat in vuln.get("Threats", [])}
                print(f"{'Threat:':<20} {', '.join(threat_descriptions)}")

                notes = [note.get("Value", "") for note in vuln.get("Notes", []) if note.get("Type") == 1]
                for note in notes:
                    clean_note = BeautifulSoup(note, "html.parser").get_text()
                    print(f"{'Description:':<20} {clean_note}")

                remediations = vuln.get("Remediations", [])
                for rem in remediations:
                    if rem.get("URL"):
                        print(f"{'Remediation URL:':<20} {rem.get('URL', 'N/A')}")
                        break

                acknowledgments = ", ".join([ack_dict.get("Value", "") for ack in vuln.get("Acknowledgments", []) for ack_dict in ack.get("Name", [])])
                print(f"{'Acknowledgments:':<20} {acknowledgments}")

                references = [ref.get("URL", "N/A") for ref in vuln.get("References", [])]
                if references:
                    print("\nReferences:")
                    for ref in references:
                        print(f"    - {ref}")
                break
        if found:
            break
    if not found:
        print(f"No details found for {cve_id}.")

def analyze_and_display_year_data(year, mincvss):
    months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    data_months = {month: get_month_vulnerabilities(year, month) for month in months}
    analyze_and_display_data(data_months, mincvss, year, "All", True)

def analyze_and_display_month_data(year, month, mincvss):
    vulnerabilities_month = get_month_vulnerabilities(year, month)
    if vulnerabilities_month is not None:
        analyze_and_display_data({month: vulnerabilities_month}, mincvss, year, month, True)

def get_month_vulnerabilities(year, month):
    file_path = DATA_DIR / f"{year}-{month}.json"
    if not file_path.exists():
        print(f"[!] No data found for {month} month of {year} year.")
        return None
    data = load_json_data(file_path)
    return data.get("Vulnerability", [])

def display_exploited_vulns(exploited_vulns):
    print(f"\nExploited ({len(exploited_vulns)})")
    print("-" * 13)
    for vuln in exploited_vulns:
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

def read_all_data_from_directory():
    all_data = {}
    for file_path in DATA_DIR.glob("*.json"):
        month_id = file_path.stem
        with file_path.open("r") as file:
            data = json.load(file)
            all_data[month_id] = data.get("Vulnerability", [])
    return all_data

def analyze_and_display_data(vulnerabilities_months, mincvss, selected_year="All", selected_month="All", display_exploited=False):
    vulnerabilities_counts = {}
    exploited_counts = {}
    category_counts = defaultdict(int)
    all_vulnerabilities = []
    all_exploited_vuln = []

    for month, vulnerabilities in vulnerabilities_months.items():
        vulnerabilities_mincvss = [vuln for vuln in vulnerabilities if get_cvss_score(vuln) != "N/A" and float(get_cvss_score(vuln)) >= mincvss]
        all_vulnerabilities += vulnerabilities_mincvss
        vulnerabilities_counts[month] = len(vulnerabilities_mincvss)

        exploited_vulns = [vuln for vuln in vulnerabilities_mincvss if extract_severity_and_exploitation(vuln)[1] == "Exploited"]
        all_exploited_vuln += exploited_vulns
        exploited_counts[month] = len(exploited_vulns)

        for vuln in vulnerabilities_mincvss:
            for threat in vuln.get("Threats", []):
                if threat.get("Type") == 0:
                    category = threat.get("Description", {}).get("Value")
                    category_counts[category] += 1

    sorted_vulnerabilities = sorted(vulnerabilities_counts.items(), key=lambda x: x[1], reverse=True)
    sorted_exploited = sorted(exploited_counts.items(), key=lambda x: x[1], reverse=True)
    sorted_categories = sorted(category_counts.items(), key=lambda x: x[1], reverse=True)

    display_overall_statistics(all_vulnerabilities, selected_year, selected_month)
    if len(sorted_vulnerabilities) > 1:
        display_monthly_distribution(sorted_vulnerabilities, sorted_exploited)
    if display_exploited:
        display_exploited_vulns(all_exploited_vuln)

def display_overall_statistics(vulnerabilities, year="All", month="All"):
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

    time_period = "All data"
    if year != "All":
        time_period = year
        if month != "All":
            time_period = f"{year}-{month}"

    print(colored(f"[x] Microsoft PatchaPalooza Statistics for {time_period}", "blue"))
    print(f"\n    {colored('Total:', 'red')}\t\t{len(vulnerabilities)} vulnerabilities.")
    print(f"    {colored('Exploited:', 'red')}\t\t{exploitation_status['Exploited']} vulnerabilities.")
    print(f"    {colored('Not Exploited:', 'red')}\t{exploitation_status['Not Exploited']} vulnerabilities.")

    sorted_categories = sorted(category_vulnerabilities.items(), key=lambda x: x[1], reverse=True)
    print(colored("\nVulnerability Categories:", "red"))
    for category, count in sorted_categories:
        print(f"    {category}: {count} vulnerabilities")

def display_monthly_distribution(sorted_vulnerabilities, exploited_stats):
    top_months = min(len(sorted_vulnerabilities), 5)
    print(colored("\n[+] Distribution across months", "blue"))
    print("-" * 44)
    print(colored(f"\nTop {top_months} Months with Most Vulnerabilities:", "red"))
    for month, count in sorted_vulnerabilities[:top_months]:
        print(f"    {month}: {count} vulnerabilities")

    print(colored(f"\nTop {top_months} Months with Most Exploited Vulnerabilities:", "red"))
    for month, count in exploited_stats[:top_months]:
        print(f"    {month}: {count} exploited vulnerabilities")

def main():
    parser = argparse.ArgumentParser(description="PatchaPalooza")

    def valid_year(year_str):
        try:
            datetime.strptime(year_str, "%Y")
            return year_str
        except ValueError:
            raise argparse.ArgumentTypeError(f"Given Year ({year_str}) not in the correct format. Expected format: YYYY.")

    def valid_month(month_str):
        try:
            datetime.strptime(month_str, "%b")
            return month_str
        except ValueError:
            raise argparse.ArgumentTypeError(f"Given Month ({month_str}) not in the correct format. Expected format: MMM.")

    def valid_cvss(cvss_str):
        try:
            cvss = float(cvss_str)
            if not 0 <= cvss <= 10:
                raise ValueError
            return cvss
        except ValueError:
            raise argparse.ArgumentTypeError(f"Given CVSS ({cvss_str}) not in the correct format. Expected float between 0.0 and 10.")

    parser.add_argument("--month", help="Specify the month for analysis in format YYYY-MMM. Defaults to current month.", default=datetime.now().strftime("%b"), type=valid_month)
    parser.add_argument("--year", help="Specify the year for analysis in format YYYY. Defaults to current year.", default=datetime.now().strftime("%Y"), type=valid_year)
    parser.add_argument("--fullyear", help="Specify the year for analysis in format YYYY. No default value.", type=valid_year)
    parser.add_argument("--mincvss", help="Specify the minimum CVSS for vulnerabilities. Defaults to 0 (all vulnerabilities).", default=0, type=valid_cvss)
    parser.add_argument("--update", help="Retrieve and store latest data.", action="store_true")
    parser.add_argument("--stats", help="Display statistics from all monthly data.", action="store_true")
    parser.add_argument("--detail", help="Provide details for a specific CVE.", default=None, type=str)

    args = parser.parse_args()
    DATA_DIR.mkdir(parents=True, exist_ok=True)

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

    if args.update:
        retrieve_and_store_data()
    elif args.detail:
        display_cve_details(args.detail)
    elif args.stats:
        all_data = read_all_data_from_directory()
        analyze_and_display_data(all_data, args.mincvss)
    else:
        if args.month and args.year and args.fullyear is None:
            analyze_and_display_month_data(args.year, args.month, args.mincvss)
        elif args.fullyear:
            analyze_and_display_year_data(args.fullyear, args.mincvss)

if __name__ == "__main__":
    main()
