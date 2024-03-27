import nmap

scanner = nmap.PortScanner()

print('Welcome')
print("<------------------------------->")

ip_addr = input('Please enter the Ip address you want to scan:')
print('Just to be sure the Ip you want to scan is :', ip_addr)
type(ip_addr)

resp = input(""" \nPlease enter the type of scan you'd want to run
             1) SYN ACK SCAN
             2)UPD SCAN
             3)COMPREHENSIVE SCAN
             4)VERBOSE SCAN
             5)COMMON VULNERABILITY
             6)CSFR VULNERABILITY
             7)SHELLSHOCK VULNERABILITY\n""")
print ("You have selected option:", resp)

if resp == '1':
    print('Nmap version:', scanner.nmap_version())
    scanner.scan(ip_addr, '-v -sS')
    print(scanner.scaninfo())
    print("Ip status:" scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports:", scanner[ip_addr]['tcp'].keys())
if resp == '2':
    print('Nmap version:' scanner.nmap_version())
    scanner.scan(ip_addr, '-v -sU')
    print(scanner.scaninfo())
    print("Ip status:" scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print('Open Ports:', scanner [ip_addr]['udp'].keys())
if resp == '3':
    print('Nmap version:', scanner.nmap_version())
    scanner.scan(ip_addr, '-p -A')
    print(scanner.scaninfo())
    print("Ip status:" scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports:", scanner[ip_addr]['tcp'].keys())
if resp == '4':
    print('Nmap version:' scanner.nmap_version())
    scanner.scan(ip_addr, '-A -T4')
    print(scanner.scaninfo())
    print("Ip status:" scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print('Open Ports:', scanner[ip_addr]['tcp'].keys())
if resp == '5':
    print('Nmap version:' scanner.nmap_version())
    scanner.scan(ip_addr, '-script vuln')
    print(scanner.scaninfo())
    print("Ip status:" scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports:", scanner[ip_addr]['tcp'].keys())
if resp == '6':
    print('Nmap version:' scanner.nmap_version())
    scanner.scan(ip_addr, ' -sV –script http-csrf')
    print(scanner.scaninfo())
    print("Ip status:" scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print('Open Ports:', scanner[ip_addr]['tcp'].keys())
if resp == '7':
    print('Nmap version:' scanner.nmap_version())
    scanner.scan(ip_addr, '-sV –script http-sherlock')
    print(scanner.scaninfo())
    print("Ip status:" scanner[ip_addr].state())
    print(scanner[ip_addr].all_protcols())
    print("Open Ports:", scanner[ip_addr]['tcp'].keys())