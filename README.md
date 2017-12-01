# alert_large_dns_packets
Using tshark to track DNS traffic and catch large (abnormal) DNS packets. 
May help with the detection of on-going DNS exfiltration attack.

For example, unusual DNS request would be:

012345678901234567890123456789012345678901234567890123456789012.foo.com

if a server or endpoint is making many of these types of large DNS requests, it's likely that internal data is being sent to an outsider.
