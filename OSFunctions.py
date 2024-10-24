import os
import subprocess
import re
import ctypes


# Check os for windows/unix families
def check_system():
    if os.name == "nt":
        return "windows"
    elif os.name == "posix":
        return "unix"
    else:
        return {os.name}


# Regex checks to whitelist MAC or IP addresses for commands
def is_valid_mac_address(mac_address):
    if mac_address is None or mac_address == "":
        return False
    mac_regex = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
    return mac_regex.match(mac_address) is not None


def is_valid_ip_address(ip_address):
    if ip_address is None or ip_address == "":
        return False
    ip_regex = re.compile(
        r'^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}$')
    return ip_regex.match(ip_address) is not None


# Look up a MAC address in the local ARP table and return its corresponding IP
def arp_lookup(mac_address):
    if is_valid_mac_address(mac_address):
        # Check the system and build the command
        os_name = check_system()
        if os_name == 'windows':
            command = "arp -a"
        elif os_name == 'unix':
            command = "arp -n"
        else:
            return ""
        try:
            # Run the command and obtain the ARP table. Shell is safe here since the command accepts no external inputs.
            output = subprocess.check_output(command, shell=True).decode()
            # Match the MAC/IP entries (filter out table headers and interfaces)
            if os_name == 'windows':
                # Windows ARP output format
                pattern = re.compile(r"([\d.]+)\s+([\d-]+\s+)?([\da-fA-F-]+)")
            elif os_name == 'unix':
                # Linux ARP output format
                pattern = re.compile(r"([\d.]+)\s+[\w]+\s+[\w]+\s+([\da-fA-F:]+)")
            else:
                return ""
            # Search the output for the MAC address
            for line in output.splitlines():
                match = pattern.search(line)
                if match:
                    ip_address = match.group(1)
                    mac_addr = match.group(3).replace('-', ':').lower()
                    if mac_addr == mac_address.lower():
                        return ip_address
            return ""
        except subprocess.CalledProcessError as e:
            raise NotImplementedError(f"Error executing arp command.")
    else:
        return ""


# Add a static entry with the give IP and MAC to the local ARP table
def add_static_arp_entry(ip_address, mac_address):
    # Check the IP and MAC are valid by whitelisting so we avoid code injection.
    if is_valid_mac_address(mac_address) and is_valid_ip_address(ip_address):
        # Check the system and build the command
        os_name = check_system()
        mac_addr = mac_address.replace(':', '-').lower()
        if os_name == 'windows':
            # Kept for possible old systems
            # command = f"netsh interface ip add neighbors \"Local Area Connection\" {ip_address} {mac_address}"
            # In Windows 10+, considering the program has to run with admin rights, this command works
            #command = f"arp -s {ip_address} {mac_addr}"
            command = f"netsh interface ipv4 delete neighbors name=\"WiFi\" address=\"{ip_address}\""
            command2 = f"netsh interface ipv4 add neighbors \"WiFi\" \"{ip_address}\" \"{mac_addr}\""
        elif os_name == 'unix':
            command = f"sudo arp -s {ip_address} {mac_addr}"
            command2 = ""
        else:
            return None
        try:
            # Run the command
            subprocess.run(command, shell=True, check=True)
            if command2 != "":
                subprocess.run(command2, shell=True, check=True)
            return ip_address, mac_address
        except subprocess.CalledProcessError as e:
            raise NotImplementedError(f"Error adding static ARP entry.")
    return None


def show_windows_notification(title, message):
    ctypes.windll.user32.MessageBoxW(0, message, title, 0x40 | 0x1)


# Show a notification window.
def show_notification_arp_mitm(attacker, victim1_mac, victim1_ip, victim2_mac, victim2_ip):
    if is_valid_mac_address(attacker) and is_valid_mac_address(victim1_mac) and is_valid_mac_address(victim2_mac) and (
            is_valid_ip_address(victim1_ip) or victim1_ip == "") and (
            is_valid_ip_address(victim2_ip) or victim2_ip == ""):
        title = "ARP mitm attack"
        message = "ARP mitm attack detected:\n\tAttacker MAC:\t" + attacker + "\n\tVictim 1:\t" + victim1_mac + "\t" + victim1_ip + "\n\tVictim2:\t" + victim2_mac + "\t" + victim2_ip + "\n"
        # Check the system and build the command
        os_name = check_system()
        if os_name == 'windows':
            show_windows_notification(title, message)
        elif os_name == 'unix':
            subprocess.run(['notify-send', title, message])
        else:
            raise NotImplementedError(f"Notifications are not implemented for OS: {os_name}")
