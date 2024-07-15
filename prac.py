import subprocess
import re

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
        print(f"Error occureed {e}")

ip = ip_address("eth0")
print(ip)

