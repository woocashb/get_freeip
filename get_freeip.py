#!/usr/bin/python2
# coding=utf-8

# Autor: lboczkaja@unity-t.pl
# Opis: skrypt automatyzujący wyszukanie kolejnego wolnego adresu w zadanej puli

import sys
import re
import socket
import errno
import colorama
from pyping import ping

class IPaddress(object):
    ip_format = r'^[0-9]{1,3}(\.[0-9]{1,3}){3}'
    reserved_ips = ('255.255.255.255', '127.0.0.1', '0.0.0.0', '169.254.0.0')
    def __init__(self, ip_address):
        if IPaddress.is_ip_address(ip_address):
            self.address =  ip_address
        else:
            return None
        self.octets = [ int(octet) for octet in self.address.split('.') ]

    def has_valid_octets(self):
        for octet in self.octets:
             if not 0 <= octet <=255:
                 return False
        return True

    @staticmethod
    def is_ip_address(ip_address):
        if re.match(IPaddress.ip_format, ip_address):
            return True
        else:
            return False

    def is_reserved_address(self):
        for reserved_ip in IPaddress.reserved_ips:
            if reserved_ip == self.address:
                return True
        if self.is_multicast_address() or self.is_broadcast_address():
            return True
        else:
            return False

    def is_network_address(self):
        if self.octets[-1] == 0:
            return True
        else:
            return False
    def is_broadcast_address(self):
        if self.octets[-1] == 255:
            return True
        else:
            return False
    def is_multicast_address(self):
        if self.octets[0] == 224:
            return True
        else:
            return False
    def __str__(self):
        return self.address

class CidrIPaddress(IPaddress):
    cidr_ip_format = r'^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$'
    def __init__(self, cidr_ip_address):
        super(CidrIPaddress, self).__init__(cidr_ip_address.split('/')[0])
        self.netmask = int(cidr_ip_address.split('/')[1])
        if not CidrIPaddress.is_cidr_ip_address(cidr_ip_address):
            return None

    @staticmethod
    def is_cidr_ip_address(cidr_ip_address):
        if re.match(CidrIPaddress.cidr_ip_format, cidr_ip_address):
            return True
        else:
            return False

    def is_unicast_address(self):
        if self.netmask == 32:
            return True
        else:
            return False

    def has_valid_netmask(self):
        if 24 <= self.netmask <=32:
            return True
        else:
            return False

    def __str__(self):
        return self.address + "/" + str(self.netmask)

def print_usage():
     print("Usage: {0} <CIDR_IP> (e.g. 192.168.2.9/32)".format(sys.argv[0]))
     sys.exit(1)

def get_freeip(cidr_ip):

    hosts_count = 2 ** (32 - cidr_ip.netmask)
    hosts_count = (hosts_count - 2) if cidr_ip.netmask == 24 else hosts_count

    host = cidr_ip.octets[3]
    network = '.'.join(map(str, cidr_ip.octets[:3]))

    if (host + hosts_count) > 255:
        print("Given host octet {0} and netmask {1} is out of byte range!".format(host, cidr_ip.netmask))
        sys.exit(6)

    for i in range(1, hosts_count + 1):
        if hosts_count == 1:
            i -= 1
        next_host = network + '.' + str(host + i)
        response =  ping(next_host, timeout=500, count=2)
        if response.ret_code == 0:
            continue
        for port in (22, 3389, 80, 443):
            try:
               if socket.create_connection((next_host, port), timeout=1):
                   break
            except socket.timeout:
                continue

            except socket.error as socket_e:
               if socket_e == errno.EHOSTUNREACH:
                 continue
            
            except OSError as os_e:
                continue
        else:
            return next_host

def parse_arguments():
   if len(sys.argv) != 2:
       print('Missing mandatory ip address in CIDR notation!')
       print_usage()
       sys.exit(255)

   if not CidrIPaddress.is_cidr_ip_address(sys.argv[1]):
       print("'{0}' is not a ip address in CIDR format!".format(sys.argv[1]))
       sys.exit(1)

   input_ip_address = CidrIPaddress(sys.argv[1])



   if not input_ip_address.has_valid_octets():
       print("Octet in CIDR ip '{0}' is out of byte range!".format(input_ip_address.address))
       sys.exit(2)

   if not input_ip_address.has_valid_netmask():
       print("Netmask '/{0}' is out of supported range!".format(input_ip_address.netmask))
       sys.exit(3)

   if input_ip_address.is_reserved_address():
       print("'{0}' is a reserved ip address!".format(input_ip_address))
       sys.exit(4)

   if input_ip_address.is_unicast_address() and input_ip_address.is_network_address():
       print("'{0}' is a network address but has a unicast address mask!".format(input_ip_address.address))
       sys.exit(5)

   return input_ip_address

if __name__ == "__main__":
    cidr_ip = parse_arguments()
    freeip = get_freeip(cidr_ip)
    if freeip:
        print("{1}{0}{2}".format(freeip, colorama.Fore.GREEN, colorama.Style.RESET_ALL))
    elif cidr_ip.is_unicast_address():
        print("{1}'{0}' is already in use!{2}".format(cidr_ip, colorama.Fore.RED, colorama.Style.RESET_ALL))
    else:
        print("No free ip address available in given '{0}' address scope!".format(cidr_ip))
