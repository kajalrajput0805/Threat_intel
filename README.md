# Airtel Threat Intelligence Platform

A full-stack Cyber Threat Intelligence Dashboard built using Flask, PostgreSQL, HTML/CSS/JavaScript, and interactive visualizations for monitoring malicious IPs, indicators, and threat trends in real time.

---

## Overview

The Airtel Threat Intelligence Platform is designed to collect, manage, and visualize cyber threat intelligence data through an interactive dashboard. The platform enables monitoring of malicious IPs, threat indicators, ASN information, and geographical threat distribution using real-time analytics and visualizations.

This project demonstrates the integration of backend threat processing with frontend visualization tools for cybersecurity monitoring and analysis.

---

## Features

- Secure User Authentication System
- Interactive Threat Intelligence Dashboard
- Threat IP Geolocation Mapping
- Daily Threat Trend Analysis
- Indicator of Compromise (IOC) Monitoring
- ISP & ASN Intelligence Analysis
- Country-wise Threat Visualization
- Real-time Threat Feed
- PostgreSQL Database Integration
- Airtel-inspired Dark UI Theme

---

# Tech Stack

## Backend
- Python
- Flask
- Flask-SQLAlchemy
- Flask-Login
- PostgreSQL

## Frontend
- HTML5
- CSS3
- JavaScript
- Chart.js
- Leaflet.js

## Database
- PostgreSQL

---

## Project Structure

```text
Threat_intel/
│
├── app/                        # Main application package
├── templates/                  # HTML templates
├── static/                     # CSS, JS, and assets
├── requirements.txt            # Python dependencies
├── run.py                      # Application entry point
├── fetch_and_store_ips.py      # Threat feed ingestion
├── create_user.py              # User creation script
├── create_client_user.py       # Client account creation
└── README.md
```

---

## Dashboard Modules

### Threat Dashboard
Displays summarized cybersecurity threat statistics and recent malicious activities.

### Threat Map
Visualizes malicious IP origins on an interactive world map using Leaflet.js.

### Threat Trends
Shows time-series threat activity and attack frequency using Chart.js.

### IOC Intelligence
Tracks indicators of compromise including suspicious IPs and related metadata.

### ASN & ISP Analysis
Provides autonomous system and ISP-based threat analysis.

---

## Visualizations

- Threat Geolocation Mapping
- Real-time Threat Trends
- Country-wise Threat Distribution
- ASN & ISP Statistics
- IOC Monitoring Charts

---

## Future Improvements

- Live Threat Feed API Integration
- Machine Learning-based Threat Prediction
- Threat Severity Scoring
- User Role Management
- SIEM Integration
- Alert Notification System

---

## Applications

- Cybersecurity Monitoring
- Threat Intelligence Analysis
- Security Operations Center (SOC) Dashboard
- IOC Tracking & Investigation
- Network Threat Visualization

---

## License

This project is for educational and research purposes.

---

## Acknowledgements

- Flask
- PostgreSQL
- Chart.js
- Leaflet.js
- Open Source Threat Intelligence Communities

---

## Author

Kajal Rajput

GitHub: https://github.com/kajalrajput0805
