# PatchaPalooza

A comprehensive tool that provides an insightful analysis of Microsoft's monthly security updates.

<img width="788" alt="image" src="https://github.com/xaitax/PatchaPalooza/assets/5014849/f9be5f38-8238-4f3e-857c-94e5cac59be6">

## 🔗 Interactive Website

For more functionality I have built a live website: 
* [https://patchapalooza.com](https://patchapalooza.com)

![image](https://github.com/xaitax/PatchaPalooza/assets/5014849/165f30a0-913a-4afb-9b4e-df90a36accfc)

## 📜 Description

PatchaPalooza uses the power of Microsoft's MSRC CVRF API to fetch, store, and analyze security update data. Designed for cybersecurity professionals, it offers a streamlined experience for those who require a quick yet detailed overview of vulnerabilities, their exploitation status, and more. This tool operates entirely offline once the data has been fetched, ensuring that your analyses can continue even without an internet connection.

## 🌟 Features

- **Retrieve Data**: Fetches the latest security update summaries directly from Microsoft.
- **Offline Storage**: Stores the fetched data for offline analysis.
- **Detailed Analysis**: Analyze specific months or get a comprehensive view across months.
- **CVE Details**: Dive deep into specifics of a particular CVE.
- **Exploitation Overview**: Quickly identify which vulnerabilities are currently being exploited.
- **CVSS Scoring**: Prioritize your patching efforts based on CVSS scores.
- **Categorized Overview**: Get a breakdown of vulnerabilities based on their types.

## 🚀 Usage

Run PatchaPalooza without arguments to see an analysis of the current month's data:
```bash
python PatchaPalooza.py
```

For a specific month's analysis:
```bash
python PatchaPalooza.py --month MMM --year YYYY
```

For a specific year's analysis:
```bash
python PatchaPalooza.py --fullyear YYYY
```

For an overall statistical overview:
```bash
python PatchaPalooza.py --stats
```

For an analysis of vulnerabilities with a minimum cvss score (can be combined in all previous use cases):
```bash
python PatchaPalooza.py --month MMM --year YYYY --mincvss 8
```

To display a detailed view of a specific CVE:
```bash
python PatchaPalooza.py --detail CVE-ID
```

To update and store the latest data:
```bash
python PatchaPalooza.py --update
```

## 📋 Requirements

- Python 3.x
- Requests library
- Termcolor library

## 👏 Credits / Contributors

[@eric-therond](https://github.com/eric-therond)

- add a mincvss argument instead of an hardcoded thresold
- add a fullyearargument to get statistics for all months of a given year
- remove the display of not exploited vulnerabilities (can be easily guessed, it's the complement of exploited vulnerabilities)

[@dinosn](https://github.com/dinosn)

- Minor fixes for the listing of Not exploitable cases

Contributions are welcome. Please feel free to fork, modify, and make pull requests or report issues.
This tool is built upon the [Microsoft's MSRC CVRF API](https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API) and is inspired by the work of [@KevTheHermit](https://github.com/Immersive-Labs-Sec/msrc-api/tree/main).

## 📌 Author

**Alexander Hagenah**
- [Twitter](https://twitter.com/xaitax)

## ⚠️ Disclaimer

This tool is meant for educational and professional purposes only. No license, so do with it whatever you like.
