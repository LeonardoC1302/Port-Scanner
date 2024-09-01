#!/usr/bin/python3
import socket
import common_ports
import re  # regex module
# import nmap

# ---------- main function ----------
def get_open_ports(target, port_range, mode=False):
  # ------------- Setting ------------- #
  print(f'\ntarget : {target}, range: {port_range} mode: {mode}')
  start_port_num = port_range[0]
  end_port_num = port_range[1] + 1
  # ------------- Setting ------------- #

  isURL = isTargetURL(target)  # Check if target is IP or URL.
  (isValid, errorString) = isTargetValid(
    target, isURL)  # check if format of www.abc.com or 192.168.0.1
  if not isValid:
    print(errorString)
    return errorString

  # Connect socket to get hostName / IpAddress
  errorString = ""
  hostNameNotFound = False
  if isURL:  ## getting the IP address
    print("is URL")
    hostname_server = target
    try:
      ip_address = socket.gethostbyname(hostname_server)
    except:
      ip_address = "error"
      errorString = 'Error: Invalid hostname'
  else:  ## getting server hostname
    print("is ipAddress")
    ip_address = str(target)
    
    try:
      hostname_server = socket.gethostbyaddr(ip_address)[0]
    except socket.gaierror:
      errorString = 'Error: Invalid IP address' #
    except:
      hostname_server = ""  # no Hostname returned.
      errorString = ''
      hostNameNotFound = True


  if (errorString != ""):
    print(errorString)
    return errorString
  else:
    print(f'hostname_server : {hostname_server}')
    print(f'ip_address : {ip_address}')

  # Socket scanning port and append in a list
  open_ports = []
  print("Scanning in progress...")
  for i in range(start_port_num, end_port_num):
    # Initialise socket and to connect.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  #ipv4, TCP
    s.settimeout(0.5)

    if s.connect_ex((ip_address, i)): 
      # print(f'Port {i} is close')
      pass
    else:
      open_ports.append(i)
      print(f'Port {i} is open')
    s.close()

  

  # ## nmap-approach . NOT WORKING. CANT INSTALL.
  # scanner = nmap.PortScanner()
  # # More options here :  https://nmap.org/book/man-briefoptions.html
  # scanner.scan(ip_address, f'{start_port_num}-{end_port_num}',
  #              "-sS -v")  
  # # print(scanner.scaninfo())
  # # print(
  # #   "IP status: ",
  # #   scanner[ip_address].state())  # check ip is reachable or not, i.e. up/down
  # # print(scanner[ip_address].all_protocols())
  # # print("Open Ports: ", scanner[ip_address]['tcp'].keys())
  # port_dict = scanner[ip_address]['tcp']
  # for key, value in x.items():
  #   if value['state'] == 'open':
  #     open_ports.append(key)

  # Returning
  if not mode:
    print(open_ports)
    return (open_ports)
  else:  # verbose mode
    returnString = ""
    returnString += f'Open ports for {hostname_server} ({ip_address})\n'
    ## if hostname not return. Use Ip address as name
    if hostNameNotFound : returnString = f'Open ports for {ip_address}\n'
    returnString += "PORT     SERVICE\n"
    for i in open_ports:
      spacing = "".center(9 - len(str(i)))
      returnString += f'{i}{spacing}{common_ports.ports_and_services[i]}\n'

    returnString = returnString.rstrip("\n")
    print(returnString)
    return (returnString)


# -------------------- sub-function---------------------
def isTargetURL(target):
  x = re.search("[a-zA-Z]", target)
  if x:
    return True
  else:
    return False


def isTargetValid(target, isURL):
  regex = '(.+\.){2,3}(.+)'
  isTargetValid = re.search(regex, target)
  errorString = ""
  result = True
  if not isTargetValid and isURL:
    errorString = 'Error: Invalid hostname'
    result = False
  elif not isTargetValid and not isURL:
    errorString = 'Error: Invalid IP address'
    result = False

  return [result, errorString]
