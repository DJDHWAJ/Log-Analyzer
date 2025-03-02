# Log Analyzer

## Overview

**Log Analyzer** is an advanced tool designed to monitor, analyze, and detect potential cybersecurity threats in log files. The tool helps security professionals and system administrators by identifying malicious activities such as **failed logins**, **brute-force attacks**, **SQL injections**, and **XSS attacks**. It provides real-time monitoring, alerts, and visualizations to enhance network and system security.

This tool also integrates **network intrusion detection** and visualizes detected threats, enabling effective cybersecurity audits and investigations.

## Features

- **Threat Detection**: Detects various attacks including:
  - Failed login attempts
  - Brute-force login attacks
  - SQL Injection
  - Cross-Site Scripting (XSS)
  
- **Real-Time Monitoring**: Automatically parses logs and detects suspicious activities.
  
- **Network Intrusion Detection**: Monitors network traffic to capture potential malicious packets (packet sniffing).
  
- **Anomaly Detection**: Detects irregular behavior using predefined patterns and alerts for suspicious activities.
  
- **Email Alerts**: Sends **email alerts** when a threat is detected.
  
- **Data Visualization**: Provides visualizations of detected threats using **Matplotlib** to help analyze attack trends.



## How It Works

### Log Parsing
- The script continuously monitors a specified log file for suspicious activities.
- It uses **regular expressions** to detect patterns such as:
  - Failed login attempts
  - Brute-force attacks
  - SQL injections
  - Cross-Site Scripting (XSS) attacks

### Threat Detection
- When the system detects a predefined attack pattern in the logs, it logs the event and sends an **email alert**.
- The alert includes:
  - Timestamp of the attack
  - Attack type (e.g., failed login, SQL injection)
  - Source IP of the potential attacker

### Real-Time Monitoring
- The **Tkinter GUI** displays captured logs and detected threats in real time.
- Users can interact with the GUI to:
  - Start/stop the capture process
  - View detected logs
  - Export the logs in **JSON format** for further analysis

### Data Visualization
- **Matplotlib** is used to visualize the detected threats over time.
- The tool generates **bar charts** that show attack types and their frequency, helping to identify trends and areas of concern quickly.

### Email Alerts
- If suspicious activity is detected, an **email alert** is sent to the specified email address.
- This enables security teams to take immediate action in response to potential threats.

## Technologies Used

- **Scapy**: A Python-based tool used for packet sniffing and network traffic analysis. It’s used to capture network packets and analyze them for malicious activities.
  
- **Tkinter**: A standard Python library for building graphical user interfaces (GUIs). It provides a simple interface to monitor network activity and view logs.

- **Logging**: Python’s built-in `logging` module is used to log various activities, including errors and alerts, helping with troubleshooting and system monitoring.

- **JSON**: A lightweight data format used to store captured packet data and detected threats in a structured format, making it easy to process and analyze.

- **Matplotlib**: A Python library used for data visualization. It’s employed here to create graphs that help in analyzing detected attacks visually.

## Example Use Cases

- **Suspicious Activity Detection**:
  - Monitor logs to detect failed login attempts, brute-force attacks, malicious payloads, and abnormal network traffic.
  
- **Real-Time Network Monitoring**:
  - Capture network traffic in real-time and identify potential network intrusions or unauthorized access.

- **Forensic Analysis**:
  - Use the tool for post-incident analysis by reviewing logs and detected threats, helping to understand the nature and scope of the attack.

- **Security Auditing**:
  - Capture and store DNS or HTTP requests for security audits and ensure compliance with best practices.

## Conclusion

**Log Analyzer** is an effective tool for detecting suspicious activity and maintaining network security. It offers real-time monitoring, email alerts, data visualization, and powerful threat detection mechanisms. With its combination of log parsing, network sniffing, and visualization, it is an invaluable asset for cybersecurity teams and system administrators.

This tool allows for the proactive identification of potential threats and provides essential insights for forensic analysis and incident response.
