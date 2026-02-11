Advanced Network Packet Analyzer with Live Dashboard
Overview

This project is a real-time network packet analyzer that captures and monitors TCP/UDP traffic, detects suspicious activity, and visualizes packet data through a live web dashboard. It is designed for network monitoring, security auditing, and threat detection purposes.

Features

Real-time capture and monitoring of TCP and UDP traffic.

Suspicious port detection and alerts for potential port scanning attacks.

Live web dashboard using Flask and JavaScript to visualize:

Source and destination IPs

Protocols (TCP/UDP)

Geolocation of IP addresses

Automated logging of network traffic for auditing and analysis.

Threaded architecture to run packet sniffing concurrently with the dashboard for real-time updates.

Tech Stack

Python – Packet capturing and analysis

Scapy – Network packet sniffing

Flask – Web dashboard backend

HTML/CSS/JavaScript – Frontend visualization

Requests – IP geolocation lookup

Threading – Concurrent execution for real-time updates

Installation

Clone this repository:

git clone <your-repo-link>
cd <repo-folder>


Install dependencies:

pip install scapy flask requests


Run the analyzer:

python analyzer.py

Usage

The dashboard will display live network packets as they are captured.

Each row shows timestamp, protocol, source/destination IP, and country.

Future Improvements

Add filtering by protocol, IP, or country.

Implement authentication for the web dashboard.

Integrate with advanced threat intelligence APIs.

Optimize IP geolocation for faster real-time updates.

