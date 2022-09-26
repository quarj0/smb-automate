import pyfiglet
import subprocess
import re

author = "### Author: hacks-and-codes ###"

print(pyfiglet.figlet_format(author, "starwars").format())

samba_search = "^(samba)|(smb)|(port 139)"
regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
def target_IP():
    test = input("enter something: ")
    if (re.search(samba_search, test)):
        check()
    else:
        print("not smb found!")

def check():
    ip_address = (input('Enter ip: '))
    if (re.search(regex, ip_address)):
        print(ip_address,"exists")
    else:
        print("Invalid ip address")


target_IP()
