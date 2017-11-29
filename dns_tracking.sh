#!/bin/sh

# To silently output to a file: ./dns_tracking.sh > dns_traffic.txt 2>/dev/null

# Input looks like:
#    1 0.000000000 104.236.104.209 → 8.8.4.4      DNS 82 Standard query 0x1fed A www.rit.edu OPT
#    2 0.042644046      8.8.4.4 → 104.236.104.209 DNS 123 Standard query response 0x1fed A www.rit.edu CNAME web01www01.rit.edu A 129.21.1.40 OPT
#    3 1.652288314 104.236.104.209 → 8.8.4.4      DNS 78 Standard query 0xfc38 A rit.edu OPT
#    4 1.667425376      8.8.4.4 → 104.236.104.209 DNS 94 Standard query response 0xfc38 A rit.edu A 129.21.1.40 OPT
#    5 6.490446423 104.236.104.209 → 8.8.4.4      DNS 88 Standard query 0x66ac A www.gallaudet.edu OPT
#    6 6.505979072      8.8.4.4 → 104.236.104.209 DNS 104 Standard query response 0x66ac A www.gallaudet.edu A 184.154.210.196 OPT
#    7 9.216198403 104.236.104.209 → 8.8.4.4      DNS 84 Standard query 0x08b1 A gallaudet.edu OPT
#    8 9.232290981      8.8.4.4 → 104.236.104.209 DNS 100 Standard query response 0x08b1 A gallaudet.edu A 134.231.4.51 OPT
#    1 0.000000000 104.236.104.209 → 8.8.4.4      DNS 68 Standard query 0x8609 A blah.com
#    2 0.268765742      8.8.4.4 → 104.236.104.209 DNS 84 Standard query response 0x8609 A blah.com A 189.113.174.199
#    3 0.269711038 104.236.104.209 → 8.8.4.4      DNS 68 Standard query 0x402e AAAA blah.com
#    4 0.285617460      8.8.4.4 → 104.236.104.209 DNS 146 Standard query response 0x402e AAAA blah.com SOA rjocpdne02.timbrasil.com.br
#    5 0.285855935 104.236.104.209 → 8.8.4.4      DNS 68 Standard query 0x9359 MX blah.com
#    6 0.301424318      8.8.4.4 → 104.236.104.209 DNS 198 Standard query response 0x9359 MX blah.com MX 10 aspmx3.googlemail.com MX 5 alt2.aspmx.l.google.com MX 1 aspmx.l.google.com MX 5 alt1.aspmx.l.google.com MX 10 aspmx2.googlemail.com

tshark -l -i eth0 -f "udp && port 53" | awk '{ if ($12 == "MX"){print "MXRES",$7,$16; system("");print ("--");} else if ($14 == "CNAME"){print "CNAMERES",$7,$17; system("");print ("--");} else if ($10 == "response" ){print "RES",$7,$15; system("");print ("--");} else{print "REQ",$7,$12; system("");}}'

## Output looks like:
# REQ 87 nyc3.sonar.digitalocean.com
# REQ 87 nyc3.sonar.digitalocean.com
# RES 103 162.243.188.200
# --
# RES 145 kim.ns.cloudflare.com
# --

# Note: The number above is the size of the request or response, if too large, it may be an ongoing DNS exfiltration attack.
