# alert_large_dns_packets
Using tshark to track DNS traffic and catch large (abnormal) DNS packets. 
May help with the detection of on-going DNS exfiltration attack.

For example, unusual DNS request would be:

visa.4603203598956889.391.1019.adrian.otis.hackerownedfoo.com

if a server or endpoint is making many of these types of large DNS requests, it's likely that internal data is being sent to an outsider.
