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
             4)VERBOSE SCAN\n""")
print ("You have selected option:", resp)

if resp == '1':
    print('Nmap version:', scanner.nmap_version())
    scanner.scan(ip_addr, '-v -sS')
    print(scanner.scaninfo())
    print("Ip status:" scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports:", scanner[ip_addr]['tcp'].keys())
    