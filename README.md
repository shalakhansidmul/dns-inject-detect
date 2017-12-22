CSE508: Network Security, Fall 2017

Homework 4: DNS Packet Injection
-------------------------------------------------------------------------------

In this assignment I have developed 
	1) an on-path DNS packet injector [dnsinject.py]
	2) a passive DNS poisoning attack detector [dnsdetect.py]
where: 
	dnsinject: capture the traffic from a network interface in promiscuous mode, and attempt
	to inject forged responses to selected DNS A requests with the goal to poison
	the resolver's cache.

and:
	dnsdetect: capture the traffic from a network interface in promiscuous mode and
	detect DNS poisoning attack attempts, such as those generated by dnsinject

This project consists of 2 main files, dnsinject.py and dnsdetect.py.

Approach for spoofing DNs reply: dnsinject.py:
---------------------------------------------

Sniffs packets that match filter (<specified on cmd line> + udp port 53) on specified interface (if not specified, use default interface.)
If a hostname file is specified, check if entry for domain name requested in captured packet is present in file.
If yes, spoof the answer with ip address mentioned in the entry in file. Do nothing, otherwise.
If no hostname file is specified, spoof answer section of all captured packets with IP address of local machine's default interface.


Approach for DNS poisoining detection : dnsdetect.py
-----------------------------------------------------

As quoted at https://www.nginx.com/resources/glossary/dns-load-balancing/
DNS load balancing relies on the fact that most clients use the first IP address they receive for a domain. In most Linux distributions, DNS by default sends the list of IP addresses in a different order each time it responds to a new client, using the round-robin method. As a result, different clients direct their requests to different servers, effectively distributing the load across the server group.

Thus, while caching the replies, I am sorting the answer ips in replies first and then concatenating into a string.
If the strings are same, then it is  a legitimate reply from a dns server.
Else it is an attack.
This is the way I have avoided false positives.

history: Dictionary of <DNS TXN ID,(src ip , dst ip , domain name requested, ttl, answer)> 
Each packet is inspected as follows:
	If TXN id forthe received packet is already present in history and it has different answers and same destination port
	a DNS poisoning attempt is detected.
	Else, it could be a legitimate response from a DNS server and it would be cached in the history for further reference. 

NOTE: with scapy-python3 stable version, there is a bug in reading packets from a pcap file.
The bug is resolved in the github version but has not been pushed to stable version yet.

Execution instructions:
-----------------------

To run dnsinject:
	python3 dnsinject.py -h hostnames.txt
To run dnsdetect:
	python3 dnsdetect.py -r capture1.pcap

capture1.pcap is generated after spoofing DNS reply for www.yandex.com using dnsinject.


output of dnsinject:
--------------------

dnsinject-master# python3 dnsinject.py -h hostnames.txt ''
WARNING: No route found for IPv6 destination :: (no default route?). This affects only IPv6
Namespace(filter='', h='hostnames.txt', i=None)
{'www.yandex.com': '10.6.6.6', 'www.instagram.com': '10.6.6.6'}
Sniffing on default interface:  wlp6s0
Not spoofing for mc.yandex.ru


Spoofing: www.yandex.com  10.6.6.6

.
Sent 1 packets.
Spoofing: www.yandex.com  10.6.6.6

.
Sent 1 packets.
Spoofing: www.yandex.com  10.6.6.6

.
Sent 1 packets.
Not spoofing for yastatic.net

Not spoofing for yastatic.net

Not spoofing for yastatic.net

Not spoofing for kiks.yandex.ru

Not spoofing for yandex.com

Not spoofing for yandex.com
----------------------------

output of dnsdetect.py:
-------------------
dnsinject-master# python3 dnsdetect.py -r capture1.pcap ''
WARNING: No route found for IPv6 destination :: (no default route?). This affects only IPv6
Namespace(filter='', i=None, r='capture1.pcap')
Reading packets from trace file:  capture1.pcap
None
2017-12-10 03:05:25 DNS poisoning attempt
TXID  47368  Request  www.yandex.com
Answer1 [10.6.6.6]
Answer2 [213.180.204.62]

2017-12-10 03:05:25 DNS poisoning attempt
TXID  47368  Request  www.yandex.com
Answer1 [10.6.6.6]
Answer2 [213.180.204.62]

2017-12-10 03:05:25 DNS poisoning attempt
TXID  41560  Request  www.yandex.com
Answer1 [213.180.204.62]
Answer2 [10.6.6.6]

-------------------------

References:
1. https://www.nginx.com/resources/glossary/dns-load-balancing/
2. https://github.com/ksasmit/NS--DNS-injector-and-detector/blob/master/dnsdetect.py
3. http://www.cs.dartmouth.edu/~sergey/netreads/local/reliable-dns-spoofing-with-python-scapy-nfqueue.html
4. http://securitynik.blogspot.com/2014/05/building-your-own-tools-with-scapy.html
