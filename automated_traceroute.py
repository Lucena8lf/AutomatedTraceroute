import signal
import sys
import subprocess
import re


# Colors
class bcolors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


def def_handler(sig, frame):
    print(f"{bcolors.FAIL}\n\n[!] Quiting...\n{bcolors.ENDC}")
    sys.exit(1)


signal.signal(signal.SIGINT, def_handler)


def run_traceroute(target):
    """
    Runs traceroute or tracert to a target and returns the raw output.
    """
    try:
        # Determine the appropriate command based on OS
        command = (
            ["tracert", target]
            if subprocess.os.name == "nt"
            else ["traceroute", target]
        )
        result = subprocess.run(command, stdout=subprocess.PIPE, text=True)
        return result.stdout
    except Exception as e:
        print(f"{bcolors.FAIL}Error running traceroute: {e}{bcolors.ENDC}")
        return None


def parse_ips(traceroute_output):
    """
    Extracts IP addresses from traceroute output using regex.
    """
    ip_regex = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    return ip_regex.findall(traceroute_output)


def sort_and_identify_gateways(ips):
    """
    Sorts IPs numerically and identifies private IPs as likely gateways.
    """
    # Sort IPs
    sorted_ips = sorted(ips, key=lambda ip: tuple(map(int, ip.split("."))))

    # Private IP ranges
    private_ranges = [
        (10, 10),  # 10.0.0.0 - 10.255.255.255
        (172, 16, 31),  # 172.16.0.0 - 172.31.255.255
        (192, 168),  # 192.168.0.0 - 192.168.255.255
    ]

    def is_private(ip):
        octets = tuple(map(int, ip.split(".")))
        return (
            (octets[0] == 10)
            or (octets[0] == 172 and 16 <= octets[1] <= 31)
            or (octets[0] == 192 and octets[1] == 168)
        )

    # Identify gateways
    gateways = [ip for ip in sorted_ips if is_private(ip)]

    return sorted_ips, gateways


def main():
    target = input("Enter the target domain (e.g., upm.es): ")
    print(f"{bcolors.OKGREEN}[*] Running traceroute...{bcolors.ENDC}")
    output = run_traceroute(target)

    if output:
        print(f"{bcolors.OKGREEN}[*] Parsing traceroute output...{bcolors.ENDC}")
        ips = parse_ips(output)

        if ips:
            sorted_ips, gateways = sort_and_identify_gateways(ips)
            print(f"{bcolors.OKGREEN}\n[*] Sorted IPs:{bcolors.ENDC}")
            print("\n".join(sorted_ips))

            print(
                f"{bcolors.OKGREEN}\n[*] Likely Gateways (Private IPs):{bcolors.ENDC}"
            )
            print("\n".join(gateways) if gateways else "None identified.")
        else:
            print(f"{bcolors.FAIL}No IPs found in traceroute output.{bcolors.ENDC}")
    else:
        print(f"{bcolors.FAIL}Traceroute failed.{bcolors.ENDC}")


if __name__ == "__main__":
    main()
