import os, re, json, pandas as pd, smtplib, logging, matplotlib.pyplot as plt
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# log stuff (not sure if this is needed but whatever)
logging.basicConfig(filename="log_file.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# config junk
ALERT_EMAIL = "your_email@example.com"
SMTP_INFO = {
    "server": "smtp.example.com",
    "port": 587,
    "user": "your_email@example.com",
    "pass": "your_password"
}

# bad stuff to look for
BAD_PATTERNS = {
    "failed_login": re.compile(r"(Failed password|authentication failure)"),
    "brute_force": re.compile(r"(multiple failed login attempts)"),
    "suspicious_ip": re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"),
    "xss_attack": re.compile(r"(<script>|javascript:|onerror=)"),
    "sql_injection": re.compile(r"(SELECT .* FROM|DROP TABLE|INSERT INTO|--|xp_)")
}

# send alert (not sure if this works lol)
def emailWarning(subj, msg):
    try:
        m = MIMEMultipart()
        m["From"], m["To"], m["Subject"] = SMTP_INFO["user"], ALERT_EMAIL, subj
        m.attach(MIMEText(msg, "plain"))

        srv = smtplib.SMTP(SMTP_INFO["server"], SMTP_INFO["port"])
        srv.starttls()
        srv.login(SMTP_INFO["user"], SMTP_INFO["pass"])
        srv.sendmail(SMTP_INFO["user"], ALERT_EMAIL, m.as_string())
        srv.quit()

        logging.info(f"Sent alert: {subj}")
    except Exception as e:
        logging.error(f"Email failed: {e}")

# read logs (should work?)
def get_logs(fpath):
    logs = []
    try:
        with open(fpath, "r", encoding="utf-8") as file:
            for line in file:
                entry = checkLogs(line)
                if entry:
                    logs.append(entry)
    except Exception as e:
        logging.error(f"oops, couldn't read logs: {e}")
    return logs

# look at logs & find bad stuff
def checkLogs(line):
    detected = []
    for k, p in BAD_PATTERNS.items():
        if p.search(line):
            logging.warning(f"Found {k}: {line.strip()}")
            detected.append({
                "timestamp": str(datetime.now()),  # timestamps r cool
                "attack_type": k,
                "log_entry": line.strip()
            })

    if detected:
        dumpJSON(detected, "outputs/alerts.json")

    return detected if detected else None

# keep an eye on logs
class LogWatcher(FileSystemEventHandler):
    def __init__(self, fpath):
        self.fpath = fpath
        self.last_size = os.path.getsize(fpath)

    def on_modified(self, event):
        if event.src_path == self.fpath:
            with open(self.fpath, "r", encoding="utf-8") as file:
                file.seek(self.last_size)
                new_lines = file.readlines()
                self.last_size = os.path.getsize(self.fpath)
                for l in new_lines:
                    checkLogs(l)

# save logs to json
def dumpJSON(data, filename):
    os.makedirs(os.path.dirname(filename), exist_ok=True)  
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

# show log stats
def makeGraph(log_data):
    if not log_data:
        logging.warning("No logs, so no graph.")
        print("Nothing to visualize.")
        return
    
    df = pd.DataFrame(log_data)
    
    if "timestamp" not in df.columns:
        logging.error("Uhh where's the 'timestamp' field??")
        print("Error: Timestamp missing.")
        return

    df["timestamp"] = pd.to_datetime(df["timestamp"])

    attack_counts = df["attack_type"].value_counts()

    plt.figure(figsize=(10, 5))
    attack_counts.plot(kind="bar", color="red")
    plt.title("Bad Stuff in Logs")
    plt.xlabel("Attack Type")
    plt.ylabel("Count")
    os.makedirs("outputs", exist_ok=True)
    plt.savefig("outputs/log_graph.png")
    plt.show()


# actually run stuff
if __name__ == "__main__":
    logfile = "example_logs/server.log"

    os.makedirs("outputs", exist_ok=True)

    # start watching logs
    watch = LogWatcher(logfile)
    obs = Observer()
    obs.schedule(watch, path=os.path.dirname(logfile), recursive=False)
    obs.start()

    # scan existing logs
    logs = get_logs(logfile)

    print(f"Total logs checked: {len(logs)}")
    if len(logs) > 0:
        print("First few:", logs[:5])

# flatten nested lists before putting into pandas
flat_logs = [e for sublist in logs for e in (sublist if isinstance(sublist, list) else [sublist])]

if flat_logs:
    makeGraph(flat_logs)
else:
    print("no bad logs found? huh.")

# just in case
if logs:
    makeGraph(logs)
