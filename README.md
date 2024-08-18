#   n e t v i s i o n 
Network Sniffer Application
A Python-based network sniffer application built with scapy for packet sniffing and customtkinter for a graphical user interface. This application allows users to:

Sniff network packets and view their details.
Perform IP lookups to retrieve information about an IP address.
Scan common ports on a given IP address.
Features
Packet Sniffing: Capture and analyze network packets in real-time.
IP Lookup: Retrieve information about a specific IP address.
Port Scanning: Scan a range of common ports on a specified IP address.
GUI Controls: Start sniffing, clear output, save results, and perform IP lookups and port scans via a user-friendly interface.
Requirements
Python 3.x
scapy library
customtkinter library
requests library
You can install the required libraries using pip:


pip install scapy customtkinter requests
Usage
Run the Application: Execute the script to launch the GUI application.

Packet Sniffing:

Click on the "Sniff" button to start capturing network packets.
View packet details in the output area.
Use the "Clear" button to clear the output.
Use the "Save" button to save the captured data to a text file.
IP Lookup:

Click on the "Ip Info" button to open the IP info window.
Enter an IP address and click "Ip Lookup" to retrieve and display information about the IP address.
Port Scanning:

Click on the "Port Scan" button to open the port scan window.
Enter an IP address and click "Port Scan" to scan common ports and display open ports.
Code Overview
psnifed(pac): Processes sniffed packets and updates the GUI with packet details.
updatefromq(): Continuously updates the GUI with new packet information.
stsniff(): Starts packet sniffing on the network.
onclicksniffbtn(): Starts sniffing and updating threads when the "Sniff" button is clicked.
onclickclearbtn(): Clears the output area when the "Clear" button is clicked.
onclicksavebtn(): Saves the output data to a text file when the "Save" button is clicked.
iplookup.ipmain(): Retrieves and displays information about an IP address.
onclickipinfobtn(): Opens the IP info window when the "Ip Info" button is clicked.
portscan.portscanner(): Scans common ports on a given IP address and updates the GUI with the results.
btnclickport(): Starts the port scanning threads when the "Port Scan" button is clicked.
portwind(): Opens the port scan window
