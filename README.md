# Home-Security-Log-Parser
A Python-based tool that parses **Windows Security Event Logs (.evtx)**, converts them to XML, and extracts meaningful information such as logon attempts, usernames, IP addresses, and timestamps.

It features two modes:
- **Log Scanner**: Monitors logs at regular intervals for suspicious activity and sends desktop notifications.
- **Search Logs**: Allows users to manually look back a specified time and review specific event logs in detail.

---

## Features

- Pulls logs from Windows `.evtx` files using PowerShell
- Converts event logs to XML format
- Extracts key information:
  - Event ID
  - Timestamp
  - Username
  - IP Address
- Detects common security events (e.g. logins, lockouts, password changes)
- Sends desktop notifications when suspicious events are detected
- Saves matched logs to a file (`matched_logs.txt`)
- Pretty-prints raw XML for deeper investigation

***Designed for educational purposes and personal use on your own network.***

---

## Purpose
This script is designed to help monitor, parse, and investigate Windows Security Event Logs (.evtx). It provides visibility into authentication events, user activity, and potential security incidents by extracting key information such as event IDs, usernames, IP addresses, and timestamps. It’s ideal for system administrators, cybersecurity students, or anyone learning about Windows log analysis.

***Note: This tool should only be used on networks you own or have explicit permission to monitor.***

---

## How It Works

The script runs in two modes:

### 1. Scanner Mode
- Continuously monitors the security log every X minutes/hours (you set the interval).
- Sends a **desktop notification** when a predefined suspicious event is found.
- Logs detailed event XML to a file named `matched_logs.txt`.

### 2. Search Mode
- Lets you **look back** over a past time window (e.g., last 30 minutes).
- Displays a **summary of logs** found.
- Allows you to **view full XML** for any entry you choose.

It uses PowerShell to access `.evtx` data, parses it into XML, and then extracts useful fields using Python regex and `minidom`.

---

## Requirements

To run this project, make sure your system meets the following requirements:

### Operating System
- **Windows** (required for accessing `.evtx` logs via PowerShell)

### Python Version
- Python **3.7 or higher**

### Admin Privileges
- Must be run with **administrator rights** to access the Security Event Log

### Python Packages

Install the following dependencies using pip:

```bash
pip install plyer schedule

> 🐍 **Note:** The following libraries are part of the Python Standard Library and do **not** require separate installation:
> - `re`
> - `time`
> - `datetime`
> - `subprocess`
> - `xml.dom.minidom`
> - `os` (if used)
> These come pre-installed with Python 3.7+.
```
## Usage

### Starting Up

**Upon starting the script**
  You will be prompted with two options.

```bash
LOG PARSER:
Welcome What would you like to do?
1.Turn on scanner
2.Search Logs
```

### Options

- **Turn on scanner**  
  Starts a scheduled scan that runs periodically to check for suspicious security events.  
  You will specify how often the scanner should run (e.g., every 10 minutes).  
  Suspicious events trigger desktop notifications and are saved to a log file.
  
```bash
Enter time interval (seconds, minutes, hours, days): minutes
Enter how often to scan (in minutes): 10
Scanner starting now...
Running, set to scan logs every 10 minutes
```

- **Search Logs**  
  Allows searching of past event logs within a user-defined time window (e.g., last 30 minutes).  
  Displays a summary of matching logs and lets you view full XML details.
```bash
How far back would you like to search?
Enter time interval (seconds, minutes, hours, days): hours
Enter how many hours to look back: 1
Searching logs from the past 1 hours...

Log #1:
  Event ID: 4624
  Date: 2025-06-21
  Time: 13:45:22
  IP Address: 192.168.1.100
  Username: JohnDoe

Enter log number (1-1) to see full XML, or press Enter to exit: 1

=== Full XML for selected log ===
<Event>
  <!-- XML content here -->
</Event>
===============================
```
---

### Inputs

- **Time Interval Units:**  
  Choose from `seconds`, `minutes`, `hours`, or `days`.

- **Frequency or Lookback Amount:**  
  Enter a positive integer representing how many units of the chosen interval to scan or look back.



---

### Outputs

- **Desktop Notifications:**  
  Alerts you when suspicious security events are detected.

- **Log File:**  
  Suspicious events are appended to `matched_logs.txt` with formatted XML and event details.

- **Console Output:**  
  Search results show summaries of matched logs with the option to view full XML

---

## Configurations
### Customizable parts of the script:
-- **HARD_PATH**--

Path to your Windows Security `.evtx` file.  
  Default:  
  ```python
  HARD_PATH = r"C:\Windows\System32\winevt\Logs\Security.evtx"
  ```
-- **SAVE_PATH**--

Not officially used in the script but can be customized as such for specific information storing.
  
  ### How to make the script save logs to `SAVE_PATH`

Import the `os` module at the top of your script if you haven’t already:

```python
import os
```
Then change this portion of the scanner function 
```python
with open("matched_logs.txt", "a", encoding="utf-8") as f:
```
To this snippet of code that allows for the current directory to be used if no SAV_PATH is specified
```python
directory = SAVE_PATH if SAVE_PATH else "."
os.makedirs(directory, exist_ok=True)
log_file_path = os.path.join(directory, "matched_logs.txt")

with open(log_file_path, "a", encoding="utf-8") as f:
```
## Notes

- `matched_logs.txt` is generated automatically by the script and should **not** be committed to your repository.  
  It’s recommended to add this file to your `.gitignore` to keep your repository clean:

- PowerShell is required on your Windows system for the script to access `.evtx` logs.

- The script must be run with **administrator privileges** to ensure it can read the Security Event Log.
