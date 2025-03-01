import os
import re
import json
import pandas as pd
import smtplib
import logging
import socket
import matplotlib.pyplot as plt
from collections import defaultdict
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from scapy.all import *
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Configure Logging
logging.basicConfig(filename="log_analyzer.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Global Variables
THREAT_IPS = set()  # Stores blacklisted IPs
ALERT_EMAIL = "your_email@example.com"
SMTP_SERVER = "smtp.example.com"
SMTP_PORT = 587
SMTP_USER = "your_email@example.com"
SMTP_PASS = "your_password"

# Regex Patterns for Log Parsing
LOG_PATTERNS = {
    "failed_login": re.compile(r"(Failed password|authentication failure)"),
    "brute_force": re.compile(r"(multiple failed login attempts)"),
    "suspicious_ip": re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"),
    "xss_attack": re.compile(r"(<script>|javascript:|onerror=)"),
    "sql_injection": re.compile(r"(SELECT .* FROM|DROP TABLE|INSERT INTO|--|xp_)"),
}

# Function to send alerts
def send_alert(subject, message):
    try:
        msg = MIMEMultipart()
        msg["From"] = SMTP_USER
        msg["To"] = ALERT_EMAIL
        msg["Subject"] = subject
        msg.attach(MIMEText(message, "plain"))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_USER, ALERT_EMAIL, msg.as_string())
        server.quit()

        logging.info(f"Alert sent: {subject}")
    except Exception as e:
        logging.error(f"Failed to send alert: {e}")

# Function to parse logs
def parse_log(file_path):
    logs = []
    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            log_entry = analyze_log_line(line)
            if log_entry:
                logs.append(log_entry)
    return logs

# Function to analyze log lines for security threats
def analyze_log_line(line):
    for attack, pattern in LOG_PATTERNS.items():
        match = pattern.search(line)
        if match:
            logging.warning(f"Detected {attack} in log: {line.strip()}")
            send_alert(f"Security Alert: {attack}", f"Suspicious activity detected:\n{line.strip()}")
            return {"timestamp": str(datetime.now()), "attack_type": attack, "log_entry": line.strip()}
    return None

# Real-time log monitoring
class LogMonitor(FileSystemEventHandler):
    def __init__(self, file_path):
        self.file_path = file_path
        self.last_size = os.path.getsize(file_path)

    def on_modified(self, event):
        if event.src_path == self.file_path:
            with open(self.file_path, "r", encoding="utf-8") as file:
                file.seek(self.last_size)
                new_lines = file.readlines()
                self.last_size = os.path.getsize(self.file_path)
                for line in new_lines:
                    analyze_log_line(line)

# Function to visualize log data
def visualize_logs(log_data):
    df = pd.DataFrame(log_data)
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    attack_counts = df["attack_type"].value_counts()

    plt.figure(figsize=(10, 5))
    attack_counts.plot(kind="bar")
    plt.title("Detected Security Threats")
    plt.xlabel("Attack Type")
    plt.ylabel("Count")
    plt.show()

# Network packet capture and analysis (Intrusion Detection)
def monitor_network_traffic(interface="eth0"):
    def packet_callback(packet):
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            if src_ip in THREAT_IPS:
                logging.warning(f"Suspicious network traffic detected from {src_ip}")
                send_alert("Suspicious Network Activity", f"Traffic detected from blacklisted IP: {src_ip}")

    sniff(iface=interface, prn=packet_callback, store=False)

# Function to detect anomalies using machine learning
def detect_anomalies(log_data):
    df = pd.DataFrame(log_data)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["hour"] = df["timestamp"].dt.hour

    unusual_activity = df.groupby("hour")["attack_type"].count().std()
    threshold = df["attack_type"].count().mean() + (2 * unusual_activity)

    anomalies = df[df["attack_type"].count() > threshold]
    
    if not anomalies.empty:
        logging.warning(f"Anomaly detected: {anomalies}")
        send_alert("Anomaly Detected in Logs", f"Unusual log activity detected:\n{anomalies}")

# Main Function
if __name__ == "__main__":
    log_file = "server.log"

    # Start real-time monitoring
    event_handler = LogMonitor(log_file)
    observer = Observer()
    observer.schedule(event_handler, path=os.path.dirname(log_file), recursive=False)
    observer.start()

    # Parse initial logs
    logs = parse_log(log_file)
    
    # Visualize log data
    visualize_logs(logs)

    # Monitor network traffic for malicious activity
    monitor_network_traffic(interface="eth0")
