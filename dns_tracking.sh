#!/bin/sh

# Only one paramater: pick the minimum size of a DNS request that will trigger an alert.

# To silently output to a file: ./dns_tracking.sh 85 > dns_traffic.txt 2>/dev/null
#
# Note: The '85' value is too low and only used for demo purposes!
# Pick a higher value that won't trigger many false positives.
#
# If the size of a request is too large, it may be a signal of an ongoing DNS exfiltration attack.
# i.e. Many large DNS requests within a short time period warrants a closer look!

SIZE="$1"
tshark -l -i eth0 -f "port 53" | awk -v size="$SIZE" '{ if ($10 == "response" ){} else if ($7 > size){system("/root/send_alert.sh LARGE_REQ " $3 " " $7 " " $12);} }'

# Output contains the IP address making the DNS request, the size of the request, and the host to be resolved.

# LARGE_REQ 104.236.104.209 132 visa.4603203598956889.391.1019.adrian.otis.hackerownedfoo.com
# LARGE_REQ 204.236.104.209 142 012345678901234567890123456789012345678901234567890123456789012.hackerownedfoo.com

# These lines are passed, one by one, onto the script that will actually send the alert.
