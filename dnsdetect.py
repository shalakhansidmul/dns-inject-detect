#!/usr/bin/python3
from scapy.all import *
import sys
import argparse
import socket
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNSQR, DNS, DNSRR
import netifaces
from datetime import datetime
dns_response_history = {}

# AUTHOR : Shalaka Sidmul [111367731]
def check_for_attack(pkt):
    global dns_response_history
    if pkt.sport == 53 and UDP in pkt and pkt[1][DNS][DNSRR].type == 1:

        dnslayer = pkt.getlayer('DNS')
        iplayer = pkt.getlayer('IP')
        number_of_answers = dnslayer.ancount
        answer_list = []
        if number_of_answers == 0:
            answer_list = []
        if number_of_answers == 1:
            answer_list.append(dnslayer.an.rdata)
        else:
            answer_list = []
            x = dnslayer.an
            for i in range(0, dnslayer.ancount):
                if x.type == 1:
                    answer_list.append(x.rdata)
                x = x.payload
            # answer = answer[:len(answer) - 1]
        ttl = pkt[1][DNS][DNSRR].ttl
        destport = pkt[IP].dport
        answer = ""
        if len(answer_list) >0:
            for ans in sorted(answer_list):
                answer += ans + ','
            answer = answer[:len(answer)-1]

        new_resp = (iplayer.src, iplayer.dst, dnslayer.qd.qname, ttl, answer, destport)

        if pkt[DNS].id in dns_response_history:
            old_response = dns_response_history[pkt[DNS].id]
            # print('DUPLICATE: ',dnslayer.qd.qname, ' id: ' ,pkt[DNS].id,'new ttl : ', pkt[1][DNS][DNSRR].ttl, ' old ttl: ', old_response[3])
            # print('new_resp: ' , new_resp)
            # print('old_response: ', old_response)
            if new_resp not in old_response:
                # if ttl are different and answers are same
                for old_resp in old_response:
                    if new_resp[4] not in old_resp[4] and new_resp[5] == old_resp[5]: #answers are diff and dest ports are same
                        # if new_resp[3] == old_resp[3]:
                        #     return
                        print(datetime.fromtimestamp(pkt.time).strftime('%Y-%m-%d %H:%M:%S') + ' DNS poisoning attempt')
                        print('TXID ' , pkt[1][DNS].id , ' Request ', pkt[1][DNS][DNSRR].rrname[:-1].decode('utf-8'))
                        print('Answer1 [' + old_resp[4] + ']')
                        print('Answer2 [' + new_resp[4] + ']\n')
                        break
                else:
                    dns_response_history[pkt[DNS].id].add(new_resp)
        else: #this is first packet
            # print('NEW: ',dnslayer.qd.qname, ' id: ',pkt[DNS].id, 'response: ', new_resp[4])
            dns_response_history[pkt[DNS].id] = set()
            dns_response_history[pkt[DNS].id].add(new_resp)


def main():
    # Reference: https://docs.python.org/2/library/argparse.html
    # specifying command line arguments
    command_line_argument_parser = argparse.ArgumentParser(description='DNS cache poisoning', add_help=False)
    # interface to listen on
    command_line_argument_parser.add_argument('-i', type=str, required=False, default=None)
    # file containing domain names and IPs to spoof
    command_line_argument_parser.add_argument('-r', type=str, required=False, default=None)
    # BPF filter for capturing packets that satisfy the filter
    command_line_argument_parser.add_argument('filter', nargs='?', type=str, default=None)

    # Capturing the arguments
    args = command_line_argument_parser.parse_args()
    print(args)

    # initialize bpf filter for sniffing
    exp = None
    # if args.filter:
    #     exp = "udp src port 53 and " + args.filter
    # else:
    #     exp = "udp src port 53"

    if args.r is None:
        if args.i is None:
            default_network_interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
            # start sniffing for packets with DNSQR layer (DNSQR: Domain Name Server Query Record)
            print('Sniffing on default interface: ', default_network_interface)
            sniff(filter=exp, iface=default_network_interface, prn=check_for_attack,
                  lfilter=lambda x: x.haslayer(DNSRR))
        else:
            print('Sniffing on specified interface: ', args.i)
            sniff(filter=exp, iface=args.i, prn=check_for_attack,
                  lfilter=lambda x: x.haslayer(DNSRR))

    else:
        # start sniffing for packets with DNSRR layer from tracefile
        print('Reading packets from trace file: ', args.r)
        print(exp)
        sniff(filter=exp, offline=args.r, store=0, prn=check_for_attack, lfilter=lambda x: x.haslayer(DNSRR))

#defining the entry point to code execution
if __name__ == "__main__":
    main()
