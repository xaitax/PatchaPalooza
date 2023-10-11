# PatchaPalooza

A comprehensive tool that provides an insightful analysis of Microsoft's monthly security updates.

<img width="755" alt="main" src="https://github.com/xaitax/PatchaPalooza/assets/5014849/02fa5585-26aa-42d6-9026-3d497bb06ac0">

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
python PatchaPalooza.py --month YYYY-MMM
```

To display a detailed view of a specific CVE:
```bash
python PatchaPalooza.py --detail CVE-ID
```

To update and store the latest data:
```bash
python PatchaPalooza.py --update
```

For an overall statistical overview:
```bash
python PatchaPalooza.py --stats
```

## 📋 Requirements

- Python 3.x
- Requests library
- Termcolor library

## 👏 Credits

This tool is built upon the [Microsoft's MSRC CVRF API](https://api.msrc.microsoft.com/cvrf/v2.0/swagger/index) and is inspired by the work of [@KevTheHermit](https://github.com/Immersive-Labs-Sec/msrc-api/tree/main).

## 📌 Author

**Alexander Hagenah**
- [Twitter](https://twitter.com/xaitax)

## ⚠️ Disclaimer

This tool is meant for educational and professional purposes only. No license, so do with it whatever you like.
