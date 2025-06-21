# This script parses Windows Security Event Logs (.evtx),
# converts them to XML format, and extracts key details
# like logon attempts, usernames, IP addresses, and more.

from plyer import notification
import time
import schedule
import re
from datetime import datetime, timedelta, timezone
import subprocess
from xml.dom import minidom 

# CONFIGURATION 
# Set the path to the Security log and define common security event IDs with descriptions.
HARD_PATH = r"C:\Windows\System32\winevt\Logs\Security.evtx"
SAVE_PATH  = ""
COMMON_SECURITY_LOGS = {
    4624: "An account was successfully logged on",
    4625: "An account failed to log on",
    4634: "An account was logged off",
    4647: "User initiated logoff",
    4672: "Special privileges assigned to new logon",
    4688: "A new process has been created",
    4689: "A process has exited",
    4697: "A service was installed in the system",
    4698: "A scheduled task was created",
    4720: "A user account was created",
    4722: "A user account was enabled",
    4723: "An attempt was made to change an account's password",
    4724: "An attempt was made to reset an account's password",
    4725: "A user account was disabled",
    4726: "A user account was deleted",
    4732: "A member was added to a security-enabled local group",
    4740: "A user account was locked out",
    4768: "A Kerberos authentication ticket (TGT) was requested",
    4769: "A Kerberos service ticket was requested",
    4771: "Kerberos pre-authentication failed",
    4776: "The domain controller attempted to validate the credentials for an account",
    4626: "User/Device claims information",
    4648: "A logon was attempted using explicit credentials",
}

# Precompiled regular expressions used to extract specific fields from each XML event.
EventBlock = re.compile(r"<Event.*?>.*?</Event>", re.DOTALL)
EventID  = re.compile(r'<EventID>(\d+)</EventID>')
EventTime = re.compile(r"SystemTime=.(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})")
EventIP = re.compile(r'Address.>([\d\.]+|-)')
EventUser = re.compile(r'<Data Name="SubjectUserName">(.*?)</Data>')


# Runs a PowerShell command to fetch event logs from a given time window.
# Converts binary .evtx to XML and returns the result as a string.
def pullFiles(**kwargs):
    timeFrequency = kwargs.get('timeFrequency', 10)
    timeInterval = kwargs.get('timeInterval', 'minutes').lower()

    delta_args = {timeInterval: timeFrequency}
    start_time = datetime.now(timezone.utc) - timedelta(**delta_args)
    formatted_start_time = start_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

    try:
        xmlFile = subprocess.run(
            ["powershell",
             "-Command",
             f"Get-WinEvent -FilterHashtable @{{Path= '{HARD_PATH}'; StartTime=[datetime]'{formatted_start_time}'}} | ForEach-Object {{$_.ToXml()}}"
             ], 
             capture_output=True,
             text=True,
             check=True
        )
        practiceXML = xmlFile.stdout
        if not practiceXML.strip():
            print("[Warning] No logs returned from the system in the specified timeframe.")
        return practiceXML

    except subprocess.CalledProcessError as e:
        print(f"[Error] Failed to run PowerShell command:\n {e}")
        return ""
    except Exception as e:
        print(f"[Error] Unexpected error in pullFiles:\n {e}")
        return ""


# Processes raw XML log data and extracts structured information.
# Returns a list of dictionaries with Event ID, timestamp, IP, username, etc.


def filter(logFile):
    eventList = re.findall(EventBlock, logFile)
    eventIdentifiersList = []
    for event in eventList:
        foundID = re.search(EventID, event)
        foundTime = re.search(EventTime, event)
        foundIP = re.search(EventIP, event)
        foundUser = re.search(EventUser,  event)

        # Parse UTC time string into datetime objects, and convert to local time for better reading
        utc_time_str = f"{foundTime.group(1)} {foundTime.group(2)}"
        utc_dt = datetime.strptime(utc_time_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        local_dt = utc_dt.astimezone()

        # Create dictionary with found info (wrapping foundID and foundIP in lists for consistency)
        eventIdentity = {
            "Event ID": foundID.group(1),
            "Date": local_dt.date(),
            "Time": local_dt.time(),
            "IP Address": foundIP.group(1) if foundIP else "-",
            "Username": foundUser.group(1) if foundUser else "Unknown User",
            "Full XML": event
        }
        eventIdentifiersList.append(eventIdentity)
    return eventIdentifiersList


        
# Prompts the user for how far back to look or how often to scan.
# Validates time interval and frequency inputs before returning them.

def get_time_input(prompt_type="lookback"):
    valid_intervals = {"seconds", "minutes", "hours", "days"}

    # input validation
    while True:
        time_interval = input("Enter time interval (seconds, minutes, hours, days): ").strip().lower()
        if time_interval in valid_intervals:
            break
        print(f"Invalid interval '{time_interval}'. Please choose from {', '.join(valid_intervals)}.")

    # allows for different text to appear depending on option chosen
    while True:
        try:
            if prompt_type == "lookback":
                frequency = int(input(f"Enter how many {time_interval} to look back: "))
            elif prompt_type == "interval":
                frequency = int(input(f"Enter how often to scan (in {time_interval}): "))
            else:
                frequency = int(input(f"Enter the number of {time_interval}: "))
            if frequency > 0:
                break
            else:
                print("Please enter a positive number.")
        except ValueError:
            print("Invalid number, please enter an integer.")

    return frequency, time_interval

# Pulls recent logs and checks each one for matches with common security event IDs.
# Sends a desktop notification and logs the full XML if suspicious activity is detected.

def scanner(timeFrequency, timeInterval):
    practiceXML = pullFiles(timeFrequency=timeFrequency, timeInterval=timeInterval)
    foundLogBool = False
    scannableLogs = re.findall(EventBlock, practiceXML)
    for log in scannableLogs:
        scannedID = re.search(EventID, log)
        if scannedID:
            scanResult = int(scannedID.group(1))
            if scanResult in COMMON_SECURITY_LOGS:
                print(f"Suspicious log detected {scannedID.group(1)}")
                notification.notify(
                    title="Warning!!!",
                    message="Suspicious activity has been found on your computer!",
                    app_name="Windows EVTX Log Parser",
                    timeout=10
                )
                foundLogBool = True

                try:
                    domFile = minidom.parseString(log)
                    formattedXML = domFile.toprettyxml(indent="  ")
                except Exception as e:
                    print(f"[Error] Failed to parse XML: {e}")
                    formattedXML = log  # fallback: raw XML string

                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                logName = COMMON_SECURITY_LOGS.get(scanResult, "Unknown Event")
                header = f"\n==== Suspicious Log Found ====\nTime: {timestamp}\nEvent ID: {scanResult} - {logName}\n===============================\n"

                with open("matched_logs.txt", "a", encoding="utf-8") as f:
                    f.write(header)
                    f.write(formattedXML + "\n\n")
    if not foundLogBool:
        print("No suspicious activity found yet.")



# Asks the user for a time window, shows a summary of matched logs, and
# Gives the option to view full, formatted XML for any selected entry.

def searchLogs():
    print("How far back would you like to search?")
    time_frequency, time_interval = get_time_input(prompt_type="lookback")

    print(f"Searching logs from the past {time_frequency} {time_interval}...")

    searchResults = pullFiles(timeFrequency=time_frequency, timeInterval=time_interval)
    filteredSearchResults = filter(searchResults)

    if not filteredSearchResults:
        print(f"No logs found within the past {time_frequency} {time_interval}.")
        return

    # Display summary info with index numbers
    for idx, logDict in enumerate(filteredSearchResults, start=1):
        print(f"Log #{idx}:")
        for key, value in logDict.items():
            if key != "Full XML":
                print(f"  {key}: {value}")
        print("")

    # Ask if user wants to see full XML of any log
    while True:
        choice = input(f"Enter log number (1-{len(filteredSearchResults)}) to see full XML, or press Enter to exit: ").strip()
        if choice == "":
            break
        if choice.isdigit():
            num = int(choice)
            if 1 <= num <= len(filteredSearchResults):
                print("\n=== Full XML for selected log ===")
                raw_xml = filteredSearchResults[num - 1]["Full XML"]
                try:
                    parsed_xml = minidom.parseString(raw_xml)
                    pretty_xml = parsed_xml.toprettyxml(indent="  ")
                    print(pretty_xml)
                except Exception as e:
                    print("[Error] Failed to format XML. Showing raw XML:")
                    print(raw_xml)
                print("===============================\n")
            else:
                print("Invalid log number.")
        else:
            print("Please enter a valid number or press Enter to exit.")

      
# Sets up and starts the scanner to run at regular intervals using the schedule library.

def startScanner():
    timeFrequency, timeInterval = get_time_input(prompt_type="interval")

    timeframeKey = {
        "seconds": schedule.every(timeFrequency).seconds,
        "minutes": schedule.every(timeFrequency).minutes,
        "hours": schedule.every(timeFrequency).hours,
        "days": schedule.every(timeFrequency).days
    }
    print('Scanner starting now...')
    print(f"Running, set to scan logs every {timeFrequency} {timeInterval}")

    timeframeKey[timeInterval].do(lambda: scanner(timeFrequency, timeInterval))
    while True:
        schedule.run_pending()
        time.sleep(1)

# Main entry point of the program. Lets the user choose between scanning or searching logs.

def main():
    choice = input("LOG PARSER:\nWelcome What would you like to do?\n1.Turn on scanner \n2.Search Logs\n")
    if choice == "1":
        startScanner()
    elif choice == "2":
        searchLogs()

main()
