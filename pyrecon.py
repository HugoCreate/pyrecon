import socket as sk
import argparse as arg
#import requests as req
#import httpx
import re
import sys
import threading

domain_pattern_global = r"""\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"""

help_text = """\nPyRecon is a reconaissance tool for fast port scanning and Web App recon.
It contains HTTP request fuzzing, URI fuzzing and etc...

commands:
[+] scan : Scan for open ports in a target (default port range 1 - 1000).
[+] fuzz : Fuzz a url to find open directories and files to access.
"""
parser = arg.ArgumentParser()

sub = parser.add_subparsers(dest="command", help="The commands available for the tool: SCAN and FUZZ.")

# Scan command and it's arguments.
scan_parser = sub.add_parser(name="scan", help="Scan command, to scan for open ports in a target.")
scan_parser.add_argument("target", help="the Domain or IP address of the target to be scanned.")
scan_parser.add_argument("-p", dest="port", help="the port or port range the user wants to scan.")

# Fuzz command and it's arguments.
fuzz_parser = sub.add_parser(name="fuzz", help="fuzzer command, to fing available directories and files in a URL.")
fuzz_parser.add_argument("url", help=r"URL to be fuzzed. Ex: 'http://site.com/PROBE'. ")
fuzz_parser.add_argument("-w", dest="wordlist", help="The wordlist to be used in the fuzzing. Yikes :D.")

args = parser.parse_args()

class Port_scanner:
    def __init__(inst, target, port):
        inst.target = target 
        inst.port = port 
    
    def resolve_domain_ip(inst):
        ip_pattern = r'''
^
(                                  # Start of IP
  (25[0-5]|                        # 250–255
   2[0-4][0-9]|                    # 200–249
   1[0-9]{2}|                      # 100–199
   [1-9][0-9]?|                    # 1–99
   0)                              # 0
  \.
){3}
(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]?|0)   # Last segment
$
'''
        domain_pattern = r"""\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"""
        if not re.fullmatch(ip_pattern, str(inst.target), re.VERBOSE) and re.fullmatch(domain_pattern, str(inst.target), re.VERBOSE):
            try:
                addr_ip = sk.gethostbyname(inst.target)
                return addr_ip
            except sk.gaierror as e:
                print(f"Couldn't resolve domain name, see the help instructions with: python pyrecon -h. ERROR: {e}")
                sys.exit()

    def scan_port(inst):
            try:
                sock = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((inst.target, int(inst.port)))
                if result == 0:
                    print(f"[+] The port {str(inst.port)} is OPEN.")
                    sock.close()
                else: 
                    print(f"[-] The port {str(inst.port)} is CLOSED.")
            except sk.gaierror as e:
                pass

    def scan_unit(inst, current_port):
        try:
            unit = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
            unit.settimeout(1)
            result = unit.connect_ex((inst.target, current_port))
            if result == 0:
                print(f"[+] The port {current_port} is OPEN.")
        except sk.gaierror as e:
            pass

    def scan_range(inst):
        if inst.port == None:
            for ports in range(1, 1001):
                threads = []
                t = threading.Thread(target=inst.scan_unit, args=(ports,))
                threads.append(t)
                t.start()
            
            for t in threads:
                t.join()
        elif "-" in inst.port:
            start, end = inst.port.split("-")
            for ports in range(int(start), int(end)):
                threads = []
                t = threading.Thread(target=inst.scan_unit, args=(ports,))
                threads.append(t)
                t.start()
            
            for t in threads:
                t.join()

class fuzzer:
    
    def __init__(self, url, wordlist):
        self.url = url 
        self.wordlist = wordlist

    def enum_wordlist(self):
        pass

def scan_option():
    scanner = Port_scanner(args.target, args.port)
    if args.port == None:
        if re.fullmatch(domain_pattern_global ,args.target, re.VERBOSE):
            print(f"\nScanning the first 1000 ports of the target: {args.target} ({scanner.resolve_domain_ip()}).")
        else:
            print(f"\nScanning the first 1000 ports of the target: {args.target}.")
        scanner.scan_range()
    elif "-" in args.port: 
        scanner.scan_range()
    else:    
        scanner.scan_port()

def fuzz_option():
    print(f"The URL is: {args.url}")
    print(f"The wordlist is: {args.wordlist}")

def main():
    if args.command == "scan":
        scan_option()
    elif args.command == "fuzz":
        fuzz_option()
    else:
        print(help_text)

        
main()
