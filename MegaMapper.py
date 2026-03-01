from argparse import RawDescriptionHelpFormatter
import socket
import time
import scapy.all as scapy
import argparse
from functools import partial
from concurrent.futures import ThreadPoolExecutor
import sys
import threading


if __name__ == "__main__":


    #Här är en parser som tar emot argument
    parser = argparse.ArgumentParser(
        formatter_class=RawDescriptionHelpFormatter,
        prog="MegaMapper",
        description="MegaMapper 1.1 ( https://github.com/Jonsson132123 )\nThis is a network tool that scans for hosts and services.\n\nExample usage: python MegaMapper.py -s 192.168.1.0/24 -p 1-1024",
        usage="MegaMapper [-t TARGET or -s SUBNET] [-p PORT(S) or --no-port]")
    parser.add_argument("-t", "--target", help="Use to specify a single IP target, EX -t 192.168.1.123", metavar="")
    parser.add_argument("-s", "--subnet", help="Use to specify a whole subnet with cidr notation, EX 192.168.1.0/24 to scan 255 IP addresses.",metavar="")
    parser.add_argument("-p", "--port", help="Use to specify port(s) to scan, EX 1-1024.",metavar="")
    parser.add_argument("--no-port", action="store_true", help="Disable port scan, can be used with subnet scan to only scan for hosts.")
    args = parser.parse_args()   
    if args.port and "-" in args.port:
        ports_split = args.port.split("-")
        hela_porten = (int(ports_split[1]) + 1)
        Port_list = range(int(ports_split[0]), int(hela_porten))
    elif args.port:
        Port_list = [int(args.port)]
    else:
        pass


    
    

    #Här skapar vi en funktion som skannar portar med ipv4 och tcp.
    #Den tar infon och sedan ger ett svar om porten är öppen eller stängd
    def scan_port(target, port):
        socketen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socketen.settimeout(0.1)
        info = socketen.connect_ex((target, port))
        socketen.close()
        port_open_list = []
        tjänst_list = []
        if info == 0:
            port_open_list.append(port)
            try: 
                tjänst = socket.getservbyport(port)
                tjänst_list.append(tjänst)
            except: 
                tjänst_list.append("Unknown")
        return port_open_list, tjänst_list

    

    #En funktion som skannar nätverket med arp request och returnerar listor med ip och mac adresser
    def host_discovery(subnet):
        request = scapy.ARP()
        request.pdst = subnet
        broadcast = scapy.Ether()
        broadcast.dst = "ff:ff:ff:ff:ff:ff"
        request_broadcast = broadcast / request
        clients = scapy.srp(request_broadcast, timeout=1)[0]
        ip_list = []
        mac_list = []
        for element in clients:
            ip_list.append(element[1].psrc)
            mac_list.append(element[1].hwsrc)
        return ip_list, mac_list


    def banner_grab(target, port):
        try:
            socketen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socketen.settimeout(2)
            socketen.connect((target, port))
            socketen.send(b"\r\n")
            banner_svar = socketen.recv(1024)
            banner_decoded = banner_svar.decode("utf-8")
            socketen.close()
            return banner_decoded
        except:
            banner_decoded = ""
            return banner_decoded


    def header():
        print("\nMegaMapper v1.1 - Networkscanner")
        print("Albin Jonsson 2026-02-26")
        print("================================\n")
    header()


    stop_event = threading.Event()
    def spinn_janne():
        spinner_list = ["|", "/", "-", "\\"]
        while not stop_event.is_set():
            for asset in spinner_list:
                sys.stdout.write(f"\r[{asset}]")
                time.sleep(0.5)
                sys.stdout.flush()
    spinner_thread = threading.Thread(target=spinn_janne)


    #Kör host_discovery om argumentet -s finns
    if args.subnet and args.no_port:
        start = time.time()
        print(f"[*] Executing host discovery on {args.subnet}...\n")
        ip_list, mac_list = host_discovery(args.subnet)
        print("")

        for nummer in range(len(ip_list)):
            print("[+]", (str(ip_list[nummer])).ljust(20), mac_list[nummer])
        end = time.time()
        print("\n[*] Scan completed in", f"{end - start:.1f}", "seconds\n")

    

    #Kör portskanningen om argumentet -t finns
    #Använder threading för snabbare portskanning
    if not args.port and args.target:
        print("No port set")
        print("Use -p for fort or port range")

    if not args.no_port and not args.port and args.subnet:
        print("No port selected\nUse -p to select ports or use --no-port to run a subnet scan\n")
    
    if args.target and args.port:
        ny_port_list = []
        ny_tjänst_list = []
        ny_banner_list = []
        start = time.time()
        print(f"[*] Executing port scan on {args.target}...")
        spinner_thread.start()
        with ThreadPoolExecutor(max_workers=100) as executor:
            func = partial(scan_port, args.target)
            port_open_list = executor.map(func, Port_list)
        for port, tjänst in port_open_list:
            if port != []:
                ny_port_list.append(port[0])
                ny_tjänst_list.append(tjänst[0])
                ny_banner_list.append(banner_grab(args.target, port[0]))
        ny_port_list.sort()
        
        
        end = time.time()
        stop_event.set()
        stop_event.is_set()
        spinner_thread.join()
        sys.stdout.write("\r      ")


        for port, tjänst, banner in zip(ny_port_list, ny_tjänst_list, ny_banner_list):   
            print("[+]", str(port).ljust(4), "open".ljust(6), tjänst.ljust(8), banner)

        print("\n[*] Scan completed in", f"{end - start:.1f}", "seconds\n")
    


    
    if args.subnet and args.port:
        start = time.time()
        ip_list, mac_list = host_discovery(args.subnet)
        

        for nummer, ip in enumerate(ip_list):
            ny_port_list = []
            ny_tjänst_list = []
            ny_banner_list = []
            new_spinner = threading.Thread(target=spinn_janne)
            new_spinner.start()

            with ThreadPoolExecutor(max_workers=100) as executor:
                func = partial(scan_port, ip)
                port_open_list = executor.map(func, Port_list)
            for port, tjänst in port_open_list:
                if port != []:
                    ny_port_list.append(port[0])
                    ny_tjänst_list.append(tjänst[0])
                    ny_banner_list.append(banner_grab(ip, port[0]))
                            
            ny_port_list.sort()

            stop_event.set()
            new_spinner.join()
            stop_event.clear()
            
            end = time.time()
            sys.stdout.write("\r    ")
            
            


            print("")
            print("[*] Host dicovered:")
            print("[host]",str(ip_list[nummer]).ljust(20), mac_list[nummer])
            for port, tjänst, banner in zip(ny_port_list, ny_tjänst_list, ny_banner_list):
                print("[+]", str(port).ljust(4), "open".ljust(6), tjänst.ljust(8), banner)
        
    


        print("")
        print("Scanning completed in", f"{end - start:.1f}", "seconds\n")
