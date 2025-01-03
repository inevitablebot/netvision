## Network Monitoring Tool

This Python-based application is designed for network administrators and cybersecurity enthusiasts to perform network packet sniffing, IP lookup, and port scanning using an intuitive GUI built with **CustomTkinter**. 

---

## Features

### 1. **Packet Sniffer**
- Monitors network traffic and displays detailed information about each packet, including:
  - Source and Destination IP
  - Protocol
  - Payload (including `POST` data if available)
  - IP Version and Flags
- Outputs packet data in a scrollable text area.
- Option to save the captured packets to a file.

### 2. **IP Lookup**
- Fetches geographical and organizational details of a given IP address using the `ipinfo.io` API.
- Displays:
  - Country, Region, City
  - Organization and Postal Code
  - Latitude/Longitude with a Google Maps link.

### 3. **Port Scanner**
- Scans a predefined list of commonly used ports for a specified IP address.
- Outputs open ports and their status in real time.

---

## Installation

### Prerequisites
1. **Python 3.8+**  
   Ensure Python is installed and added to your system PATH.
2. **Required Python Libraries**  
   Install dependencies by running:
   ```bash
   pip install -r requirements.txt
   ```

   Contents of `requirements.txt`:
   ```
   scapy
   customtkinter
   requests
   ```
3. **Additional Files**
   - Include a valid `logo.ico` file for application branding.

### Running the Application
Execute the main script:
```bash
python network_monitor.py
```

---

## Usage

### Packet Sniffer
1. Launch the application.
2. Click the **Sniff** button to start monitoring packets on the default network interface.
3. View real-time traffic details in the text area.
4. Use **Clear** to reset the display or **Save** to store results.

### IP Lookup
1. Click the **IP Info** button to open the IP Lookup tool.
2. Enter the target IP address and click **IP Lookup**.
3. Detailed IP information will appear in the output area.

### Port Scanner
1. Click the **Port Scan** button to open the Port Scanning tool.
2. Enter the target IP address and click **Port Scan**.
3. Real-time results for open ports will appear.

---

## Code Overview

### Key Modules
- **`scapy.all`**: For packet sniffing and network analysis.
- **`customtkinter`**: For creating a modern and responsive GUI.
- **`requests`**: For fetching IP information from external APIs.
- **`socket`**: For scanning ports.

### Multithreading
- Ensures smooth GUI operation by offloading sniffing and scanning tasks to separate threads.

---


1. **Main Sniffer Window**
   - Real-time packet details display.
   - Buttons for sniffing, clearing, saving, IP lookup, and port scanning.

2. **IP Lookup Tool**
   - Simple interface to fetch IP details.

3. **Port Scanning Tool**
   - Displays the status of common ports in real time.

---

## License
This project is open-source and licensed under the MIT License. Contributions are welcome!

---

## Future Enhancements
- Add more advanced filtering options for packet sniffing.
- Implement user-defined port ranges for scanning.
- Enhance UI design with themes and custom fonts.
