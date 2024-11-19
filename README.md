# Browser Fingerprint Collector

This repository contains a simple HTML page that collects detailed fingerprinting information from a visitor's browser and operating system. The collected data is sent to a specified server endpoint after a 2-second delay when the user visits the page. The script is designed to be compatible with major browsers across different operating systems.

## Features

- **Cross-Browser Compatibility:** Works with major browsers like Chrome, Firefox, Edge, Safari, etc.
- **OS Agnostic:** Collects information across different operating systems including Windows, macOS, Linux, and more.
- **Data Collection:** Gathers detailed information such as User-Agent, screen resolution, installed browser plugins, platform, language preference, timezone, hardware concurrency, device memory, connection type, touch support, and more.
- **2-Second Delay:** A 2-second delay is introduced before the data collection starts to avoid detection and ensure the page loads smoothly for the user.
- **Customizable Endpoint:** The data is sent to a customizable server endpoint (`/Results/efil/` by default).

## How It Works

1. **HTML Page:** A simple "Hello World" HTML page with embedded JavaScript.
2. **JavaScript Execution:** After a 2-second delay, the JavaScript collects various details about the user's browser and environment.
3. **Data Transmission:** The collected data is sent via an image request to the specified server endpoint.

## Usage

### Deploying the Page

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/crtvrffnrt/browser-fingerprint-collector.git
   cd browser-fingerprint-collector
   python3 -m browsercatch.py 8080
   ```
