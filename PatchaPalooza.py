#!/usr/bin/env python3
import requests
import argparse
from termcolor import colored
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from bs4 import BeautifulSoup
import json
import re

BASE_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/"
HEADERS = {"Accept": "application/json"}
DATA_DIR = Path("msrc_data")


def ensure_directory_exists(directory: Path):
    directory.mkdir(parents=True, exist_ok=True)


def load_json_data(file_path: Path) -> dict:
    try:
        with file_path.open("r", encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError as e:
        print(f"File not found: {file_path} - {e}")
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from {file_path} - {e}")
    except Exception as e:
        print(f"Unexpected error reading {file_path}: {e}")
    return {}


def retrieve_all_summaries():
    endpoint = f"{BASE_URL}updates"
    try:
        response = requests.get(endpoint, headers=HEADERS)
        response.raise_for_status()
        return response.json().get("value", [])
    except requests.HTTPError as e:
        print(
            f"HTTP error occurred: {e.response.status_code} - {e.response.text}")
    except requests.RequestException as e:
        print(f"An error occurred: {e}")
    return []


def retrieve_and_store_data():
    ensure_directory_exists(DATA_DIR)
    summaries = retrieve_all_summaries()

    for summary in summaries:
        month_id = summary["ID"]
        file_path = DATA_DIR / f"{month_id}.json"
        if not file_path.exists():
            try:
                response = requests.get(
                    f"{BASE_URL}cvrf/{month_id}", headers=HEADERS)
                response.raise_for_status()
                with file_path.open("w", encoding="utf-8") as file:
                    json.dump(response.json(), file)
                print(colored(f"[+] Stored data for {month_id}", "green"))
            except requests.HTTPError as e:
                print(
                    f"HTTP error occurred for {month_id}: {e.response.status_code} - {e.response.text}")
            except requests.RequestException as e:
                print(
                    f"An error occurred while retrieving data for {month_id}: {e}")

    # Recalculate which months have stored data.
    stored_ids = {file_path.stem for file_path in DATA_DIR.glob("*.json")}
    all_months = {summary["ID"] for summary in summaries}
    missing_months = all_months - stored_ids
    if missing_months:
        print(
            colored(f"[-] Missing data for months: {', '.join(missing_months)}", "red"))
    else:
        print(colored("[+] Data fully updated.", "green"))

    last_update_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(colored(f"[i] Last updated: {last_update_time}", "blue"))


def extract_severity_and_exploitation(vuln: dict) -> (str, str):
    severity = "Unknown"
    exploited_status = "Not Exploited"
    for threat in vuln.get("Threats", []):
        description = threat.get("Description", {}).get("Value", "")
        if "Exploited:Yes" in description:
            exploited_status = "Exploited"
        elif "Exploited:No" in description or "Not Exploitable" in description:
            if exploited_status != "Exploited":
                exploited_status = "Not Exploitable"
        if severity == "Unknown":
            match = re.search(r"Severity:\s*([^\s]+)", description)
            if match:
                severity = match.group(1)
    return severity, exploited_status


def get_cvss_score(vuln: dict):
    cvss_sets = vuln.get("CVSSScoreSets", [])
    if cvss_sets:
        return cvss_sets[0].get("BaseScore", "N/A")
    return "N/A"


def cvss_float_value(vuln: dict) -> float:
    """Helper to convert a vulnerability's CVSS score to a float for sorting."""
    score = get_cvss_score(vuln)
    try:
        return float(score) if score != "N/A" else 0.0
    except ValueError:
        return 0.0


def display_cve_details(cve_id: str):
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
                severity, exploited_status = extract_severity_and_exploitation(
                    vuln)
                exploited_color = "red" if exploited_status == "Exploited" else "green"
                print(
                    f"{'Status:':<20} {colored(exploited_status, exploited_color)}")
                threat_descriptions = {
                    threat.get("Description", {}).get("Value", "N/A") for threat in vuln.get("Threats", [])
                }
                print(f"{'Threat:':<20} {', '.join(threat_descriptions)}")
                notes = [
                    note.get("Value", "") for note in vuln.get("Notes", []) if note.get("Type") == 1
                ]
                for note in notes:
                    clean_note = BeautifulSoup(note, "html.parser").get_text()
                    print(f"{'Description:':<20} {clean_note}")
                remediations = vuln.get("Remediations", [])
                for rem in remediations:
                    if rem.get("URL"):
                        print(f"{'Remediation URL:':<20} {rem.get('URL', 'N/A')}")
                        break
                acknowledgments = ", ".join([
                    ack_dict.get("Value", "")
                    for ack in vuln.get("Acknowledgments", [])
                    for ack_dict in ack.get("Name", [])
                ])
                print(f"{'Acknowledgments:':<20} {acknowledgments}")
                references = [ref.get("URL", "N/A")
                              for ref in vuln.get("References", [])]
                if references:
                    print("\nReferences:")
                    for ref in references:
                        print(f"    - {ref}")
                break
        if found:
            break
    if not found:
        print(f"No details found for {cve_id}.")


def get_month_vulnerabilities(year: str, month: str):
    file_path = DATA_DIR / f"{year}-{month}.json"
    if not file_path.exists():
        print(f"[!] No data found for {month} month of {year} year.")
        return None
    data = load_json_data(file_path)
    return data.get("Vulnerability", [])


def display_vulns(category_title: str, vulns: list):
    print(f"\n{category_title} ({len(vulns)})")
    print("-" * (len(category_title) + 5))
    sorted_vulns = sorted(vulns, key=cvss_float_value, reverse=True)
    for vuln in sorted_vulns:
        cve = vuln.get("CVE", "")
        title = vuln.get("Title", {}).get("Value", "")
        cvss_score = get_cvss_score(vuln)
        print(f"    {cve} - {cvss_score} - {title}")


def count_type(search_type: str, all_vulns: list) -> int:
    count = 0
    for vuln in all_vulns:
        for threat in vuln.get("Threats", []):
            if threat.get("Type") == 0:
                desc = threat.get("Description", {}).get("Value", "").strip()
                if search_type == "Edge - Chromium":
                    prod_ids = threat.get("ProductID", [])
                    if desc == "Edge - Chromium" or (prod_ids and prod_ids[0] == "11655"):
                        count += 1
                        break
                else:
                    if desc == search_type:
                        count += 1
                        break
    return count


def read_all_data_from_directory():
    all_data = {}
    for file_path in DATA_DIR.glob("*.json"):
        month_id = file_path.stem
        with file_path.open("r", encoding="utf-8") as file:
            data = json.load(file)
            all_data[month_id] = data.get("Vulnerability", [])
    return all_data


def display_overall_statistics(vulnerabilities: list, year="All", month="All"):
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
        category_vulnerabilities[category] = count_type(
            category, vulnerabilities)
    time_period = "All data"
    if year != "All":
        time_period = year
        if month != "All":
            time_period = f"{year}-{month}"
    print(
        colored(f"[x] Microsoft PatchaPalooza Statistics for {time_period}", "blue"))
    print(
        f"\n    {colored('Total:', 'red')}\t\t{len(vulnerabilities)} vulnerabilities.")
    print(
        f"    {colored('Exploited:', 'red')}\t\t{exploitation_status['Exploited']} vulnerabilities.")
    print(
        f"    {colored('Not Exploitable:', 'red')}\t{exploitation_status['Not Exploitable']} vulnerabilities.")
    print(
        f"    {colored('Not Exploited:', 'red')}\t{exploitation_status['Not Exploited']} vulnerabilities.")
    sorted_categories = sorted(
        category_vulnerabilities.items(), key=lambda x: x[1], reverse=True)
    print(colored("\nVulnerability Categories:\n", "blue"))
    for category, count in sorted_categories:
        print(f"    {category}: {count} vulnerabilities")


def display_monthly_distribution(sorted_vulnerabilities: list, exploited_stats: list):
    top_months = min(len(sorted_vulnerabilities), 5)
    print(colored("\n[+] Distribution across months", "blue"))
    print("-" * 44)
    print(
        colored(f"\nTop {top_months} Months with Most Vulnerabilities:", "red"))
    for month, count in sorted_vulnerabilities[:top_months]:
        print(f"    {month}: {count} vulnerabilities")
    print(colored(
        f"\nTop {top_months} Months with Most Exploited Vulnerabilities:", "red"))
    for month, count in exploited_stats[:top_months]:
        print(f"    {month}: {count} exploited vulnerabilities")


def analyze_and_display_data(vulnerabilities_months: dict, mincvss: float,
                             selected_year="All", selected_month="All", display_exploited=False):
    vulnerabilities_counts = {}
    exploited_counts = {}
    all_vulnerabilities = []
    all_exploited_vuln = []

    for month, vulnerabilities in vulnerabilities_months.items():
        valid_vulns = []
        for vuln in vulnerabilities:
            cvss = get_cvss_score(vuln)
            if cvss != "N/A" and float(cvss) >= mincvss:
                valid_vulns.append(vuln)
        all_vulnerabilities += valid_vulns
        vulnerabilities_counts[month] = len(valid_vulns)
        exploited_vulns = [v for v in valid_vulns if extract_severity_and_exploitation(v)[
            1] == "Exploited"]
        all_exploited_vuln += exploited_vulns
        exploited_counts[month] = len(exploited_vulns)

    sorted_vulnerabilities = sorted(
        vulnerabilities_counts.items(), key=lambda x: x[1], reverse=True)
    sorted_exploited = sorted(exploited_counts.items(),
                              key=lambda x: x[1], reverse=True)

    display_overall_statistics(
        all_vulnerabilities, selected_year, selected_month)
    if len(sorted_vulnerabilities) > 1:
        display_monthly_distribution(sorted_vulnerabilities, sorted_exploited)

    if display_exploited:
        display_vulns("Exploited", all_exploited_vuln)
        not_exploitable_vulns = [
            v for v in all_vulnerabilities if extract_severity_and_exploitation(v)[1] == "Not Exploitable"
        ]
        if not_exploitable_vulns:
            display_vulns("Not Exploitable", not_exploitable_vulns)
        not_exploited_vulns = [
            v for v in all_vulnerabilities if extract_severity_and_exploitation(v)[1] == "Not Exploited"
        ]
        if not_exploited_vulns:
            display_vulns("Not Exploited", not_exploited_vulns)


def analyze_and_display_year_data(year: str, mincvss: float):
    months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
              "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    data_months = {}
    for month in months:
        vulns = get_month_vulnerabilities(year, month)
        if vulns is not None:
            data_months[month] = vulns
    if not data_months:
        print(f"[!] No data available for the year {year}.")
        return
    analyze_and_display_data(data_months, mincvss, year, "All", True)


def analyze_and_display_month_data(year: str, month: str, mincvss: float):
    vulnerabilities_month = get_month_vulnerabilities(year, month)
    if vulnerabilities_month is not None:
        analyze_and_display_data(
            {month: vulnerabilities_month}, mincvss, year, month, True)


def main():
    parser = argparse.ArgumentParser(description="PatchaPalooza")

    def valid_year(year_str: str) -> str:
        try:
            datetime.strptime(year_str, "%Y")
            return year_str
        except ValueError:
            raise argparse.ArgumentTypeError(
                f"Given Year ({year_str}) not in the correct format. Expected format: YYYY."
            )

    def valid_month(month_str: str) -> str:
        try:
            normalized = month_str.title()
            datetime.strptime(normalized, "%b")
            return normalized
        except ValueError:
            raise argparse.ArgumentTypeError(
                f"Given Month ({month_str}) not in the correct format. Expected format: MMM."
            )

    def valid_cvss(cvss_str: str) -> float:
        try:
            cvss = float(cvss_str)
            if not 0 <= cvss <= 10:
                raise ValueError
            return cvss
        except ValueError:
            raise argparse.ArgumentTypeError(
                f"Given CVSS ({cvss_str}) not in the correct format. Expected float between 0.0 and 10."
            )

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--update", help="Retrieve and store latest data.", action="store_true")
    group.add_argument(
        "--detail", help="Provide details for a specific CVE.", type=str)
    group.add_argument(
        "--stats", help="Display statistics from all monthly data.", action="store_true")

    parser.add_argument("--month",
                        help="Specify the month for analysis in format MMM. Defaults to current month.",
                        default=datetime.now().strftime("%b"),
                        type=valid_month)
    parser.add_argument("--year",
                        help="Specify the year for analysis in format YYYY. Defaults to current year.",
                        default=datetime.now().strftime("%Y"),
                        type=valid_year)
    parser.add_argument("--fullyear",
                        help="Specify the year for full-year analysis in format YYYY.",
                        type=valid_year)
    parser.add_argument("--mincvss",
                        help="Specify the minimum CVSS for vulnerabilities. Defaults to 0 (all vulnerabilities).",
                        default=0, type=valid_cvss)

    args = parser.parse_args()
    ensure_directory_exists(DATA_DIR)

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
        if args.fullyear:
            analyze_and_display_year_data(args.fullyear, args.mincvss)
        else:
            analyze_and_display_month_data(args.year, args.month, args.mincvss)


if __name__ == "__main__":
    main()
