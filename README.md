# WireShark Configuration

This is my personal Wireshark configuration. This aids me in troubleshooting by adding new columns and filter buttons to help identify networking and or machine configuration issues. 

*Filter Buttons and Column settings*

Filter Buttons

"TRUE","Traffic//Auth//All","kerberos or ntlmssp or radius or ldap.authentication or udp.port in {88,1645,1646,1812,1813} or tcp.port ==88 or imap.request.username or mapi.EcDoConnect.name or kerberos.CNameString or tls.handshake.extensions_server_name in {\x22autologon.microsoftazuread-sso.com\x22 , \x22adnotifications.windowsazure.com\x22 , \x22login.microsoftonline.com\x22 , \x22autologon.microsoftazuread-sso.us\x22 , \x22adnotifications.windowsazure.us\x22 , \x22logon.microsoftonline.us\x22 , \x22device.login.microsoftonline.com\x22} or (tls.handshake.type == 11 and !tcp.srcport == 443) or http.proxy_authenticate","Filter on Kerberos, NTLM, Radius auth or Cert Auth"

"TRUE","Traffic//Auth//External destination Auth","!(ip.src in {0.0.0.0/8 , 10.0.0.0/8 , 100.64.0.0/10 , 127.0.0.0/8 , 127.0.53.53 , 169.254.0.0/16 , 172.16.0.0/12 , 192.0.0.0/24 , 192.0.2.0/24 , 192.168.0.0/16 , 198.18.0.0/15 , 198.51.100.0/24 , 203.0.113.0/24 , 224.0.0.0/4 , 240.0.0.0/4 , 255.255.255.255/32} or ipv6.src in {::/128 , ::1/128 , ::ffff:0:0/96 , ::/96 , 100::/64 , 2001:10::/28 , 2001:db8::/32 , fc00::/7 , fe80::/10 , fec0::/10 , ff00::/8 , 2002::/24 , 2002:a00::/24 , 2002:7f00::/24 , 2002:a9fe::/32 , 2002:ac10::/28 , 2002:c000::/40 , 2002:c000:200::/40 , 2002:c0a8::/32 , 2002:c612::/31 , 2002:c633:6400::/40 , 2002:cb00:7100::/40 , 2002:e000::/20 , 2002:f000::/20 , 2002:ffff:ffff::/48 , 2001::/40 , 2001:0:a00::/40 , 2001:0:7f00::/40 , 2001:0:a9fe::/48 , 2001:0:ac10::/44 , 2001:0:c000::/56 , 2001:0:c000:200::/56 , 2001:0:c0a8::/48 , 2001:0:c612::/47 , 2001:0:c633:6400::/56 , 2001:0:cb00:7100::/56 , 2001:0:e000::/36 , 2001:0:f000::/36 , 2001:0:ffff:ffff::/64} or ip.dst in {0.0.0.0/8 , 10.0.0.0/8 , 100.64.0.0/10 , 127.0.0.0/8 , 127.0.53.53 , 169.254.0.0/16 , 172.16.0.0/12 , 192.0.0.0/24 , 192.0.2.0/24 , 192.168.0.0/16 , 198.18.0.0/15 , 198.51.100.0/24 , 203.0.113.0/24 , 224.0.0.0/4 , 240.0.0.0/4 , 255.255.255.255/32} or ipv6.dst in {::/128 , ::1/128 , ::ffff:0:0/96 , ::/96 , 100::/64 , 2001:10::/28 , 2001:db8::/32 , fc00::/7 , fe80::/10 , fec0::/10 , ff00::/8 , 2002::/24 , 2002:a00::/24 , 2002:7f00::/24 , 2002:a9fe::/32 , 2002:ac10::/28 , 2002:c000::/40 , 2002:c000:200::/40 , 2002:c0a8::/32 , 2002:c612::/31 , 2002:c633:6400::/40 , 2002:cb00:7100::/40 , 2002:e000::/20 , 2002:f000::/20 , 2002:ffff:ffff::/48 , 2001::/40 , 2001:0:a00::/40 , 2001:0:7f00::/40 , 2001:0:a9fe::/48 , 2001:0:ac10::/44 , 2001:0:c000::/56 , 2001:0:c000:200::/56 , 2001:0:c0a8::/48 , 2001:0:c612::/47 , 2001:0:c633:6400::/56 , 2001:0:cb00:7100::/56 , 2001:0:e000::/36 , 2001:0:f000::/36 , 2001:0:ffff:ffff::/64}) and (kerberos or ntlmssp or radius or ldap.authentication or udp.port in {88,1645,1646,1812,1813} or tcp.port ==88 or imap.request.username or mapi.EcDoConnect.name or kerberos.CNameString or tls.handshake.extensions_server_name in {\x22autologon.microsoftazuread-sso.com\x22 , \x22adnotifications.windowsazure.com\x22 , \x22login.microsoftonline.com\x22 , \x22autologon.microsoftazuread-sso.us\x22 , \x22adnotifications.windowsazure.us\x22 , \x22login.microsoftonline.us\x22 , \x22device.login.microsoftonline.com\x22} or (tls.handshake.type == 11 and !tcp.srcport == 443) or http.proxy_authenticate)","External/Internet destination Authenication"

"TRUE","Traffic//Auth//On premise Auth","(ip.src in {0.0.0.0/8 , 10.0.0.0/8 , 100.64.0.0/10 , 127.0.0.0/8 , 127.0.53.53 , 169.254.0.0/16 , 172.16.0.0/12 , 192.0.0.0/24 , 192.0.2.0/24 , 192.168.0.0/16 , 198.18.0.0/15 , 198.51.100.0/24 , 203.0.113.0/24 , 224.0.0.0/4 , 240.0.0.0/4 , 255.255.255.255/32} or ipv6.src in {::/128 , ::1/128 , ::ffff:0:0/96 , ::/96 , 100::/64 , 2001:10::/28 , 2001:db8::/32 , fc00::/7 , fe80::/10 , fec0::/10 , ff00::/8 , 2002::/24 , 2002:a00::/24 , 2002:7f00::/24 , 2002:a9fe::/32 , 2002:ac10::/28 , 2002:c000::/40 , 2002:c000:200::/40 , 2002:c0a8::/32 , 2002:c612::/31 , 2002:c633:6400::/40 , 2002:cb00:7100::/40 , 2002:e000::/20 , 2002:f000::/20 , 2002:ffff:ffff::/48 , 2001::/40 , 2001:0:a00::/40 , 2001:0:7f00::/40 , 2001:0:a9fe::/48 , 2001:0:ac10::/44 , 2001:0:c000::/56 , 2001:0:c000:200::/56 , 2001:0:c0a8::/48 , 2001:0:c612::/47 , 2001:0:c633:6400::/56 , 2001:0:cb00:7100::/56 , 2001:0:e000::/36 , 2001:0:f000::/36 , 2001:0:ffff:ffff::/64} or ip.dst in {0.0.0.0/8 , 10.0.0.0/8 , 100.64.0.0/10 , 127.0.0.0/8 , 127.0.53.53 , 169.254.0.0/16 , 172.16.0.0/12 , 192.0.0.0/24 , 192.0.2.0/24 , 192.168.0.0/16 , 198.18.0.0/15 , 198.51.100.0/24 , 203.0.113.0/24 , 224.0.0.0/4 , 240.0.0.0/4 , 255.255.255.255/32} or ipv6.dst in {::/128 , ::1/128 , ::ffff:0:0/96 , ::/96 , 100::/64 , 2001:10::/28 , 2001:db8::/32 , fc00::/7 , fe80::/10 , fec0::/10 , ff00::/8 , 2002::/24 , 2002:a00::/24 , 2002:7f00::/24 , 2002:a9fe::/32 , 2002:ac10::/28 , 2002:c000::/40 , 2002:c000:200::/40 , 2002:c0a8::/32 , 2002:c612::/31 , 2002:c633:6400::/40 , 2002:cb00:7100::/40 , 2002:e000::/20 , 2002:f000::/20 , 2002:ffff:ffff::/48 , 2001::/40 , 2001:0:a00::/40 , 2001:0:7f00::/40 , 2001:0:a9fe::/48 , 2001:0:ac10::/44 , 2001:0:c000::/56 , 2001:0:c000:200::/56 , 2001:0:c0a8::/48 , 2001:0:c612::/47 , 2001:0:c633:6400::/56 , 2001:0:cb00:7100::/56 , 2001:0:e000::/36 , 2001:0:f000::/36 , 2001:0:ffff:ffff::/64}) and (kerberos or ntlmssp or radius or ldap.authentication or udp.port in {88,1645,1646,1812,1813} or tcp.port ==88 or imap.request.username or mapi.EcDoConnect.name or kerberos.CNameString or tls.handshake.extensions_server_name in {\x22autologon.microsoftazuread-sso.com\x22 , \x22adnotifications.windowsazure.com\x22 , \x22login.microsoftonline.com\x22 , \x22autologon.microsoftazuread-sso.us\x22 , \x22adnotifications.windowsazure.us\x22 , \x22login.microsoftonline.us\x22 , \x22device.login.microsoftonline.com\x22} or (tls.handshake.type == 11 and !tcp.srcport == 443) or http.proxy_authenticate)","On permise (Bogon source and destination) Authenication"

"TRUE","Traffic//Auth//Username","radius.User_Name or ntlmssp.auth.username or imap.request.username or mapi.EcDoConnect.name or kerberos.CNameString or (tls.handshake.type == 13 and x509sat.DirectoryString == 1 and !tls.handshake.type == 2)","Find auth frames with username present"

"TRUE","Traffic//Bad traffic","proxy.bad_format or radius.3GPP2_Bad_PPP_Frame_Count or radius.3GPP2_Bad_PPP_Frame_Count.len or quic.bad_retry or smb_pipe.bad_type or smb2.bad_response or smb2.bad_signature or udp.length.bad or udp.length.bad_zero","Bad frames for Proxy, RADIUS, QUIC, SMB and UDP"

"TRUE","Traffic//Bogon (internal traffic)","\x0a!(icmp.type == 11) and (ip.src in {0.0.0.0/8 , 10.0.0.0/8 , 100.64.0.0/10 , 127.0.0.0/8 , 127.0.53.53 , 169.254.0.0/16 , 172.16.0.0/12 , 192.0.0.0/24 , 192.0.2.0/24 , 192.168.0.0/16 , 198.18.0.0/15 , 198.51.100.0/24 , 203.0.113.0/24 , 224.0.0.0/4 , 240.0.0.0/4 , 255.255.255.255/32} or ipv6.src in {::/128 , ::1/128 , ::ffff:0:0/96 , ::/96 , 100::/64 , 2001:10::/28 , 2001:db8::/32 , fc00::/7 , fe80::/10 , fec0::/10 , ff00::/8 , 2002::/24 , 2002:a00::/24 , 2002:7f00::/24 , 2002:a9fe::/32 , 2002:ac10::/28 , 2002:c000::/40 , 2002:c000:200::/40 , 2002:c0a8::/32 , 2002:c612::/31 , 2002:c633:6400::/40 , 2002:cb00:7100::/40 , 2002:e000::/20 , 2002:f000::/20 , 2002:ffff:ffff::/48 , 2001::/40 , 2001:0:a00::/40 , 2001:0:7f00::/40 , 2001:0:a9fe::/48 , 2001:0:ac10::/44 , 2001:0:c000::/56 , 2001:0:c000:200::/56 , 2001:0:c0a8::/48 , 2001:0:c612::/47 , 2001:0:c633:6400::/56 , 2001:0:cb00:7100::/56 , 2001:0:e000::/36 , 2001:0:f000::/36 , 2001:0:ffff:ffff::/64} or ip.dst in {0.0.0.0/8 , 10.0.0.0/8 , 100.64.0.0/10 , 127.0.0.0/8 , 127.0.53.53 , 169.254.0.0/16 , 172.16.0.0/12 , 192.0.0.0/24 , 192.0.2.0/24 , 192.168.0.0/16 , 198.18.0.0/15 , 198.51.100.0/24 , 203.0.113.0/24 , 224.0.0.0/4 , 240.0.0.0/4 , 255.255.255.255/32} or ipv6.dst in {::/128 , ::1/128 , ::ffff:0:0/96 , ::/96 , 100::/64 , 2001:10::/28 , 2001:db8::/32 , fc00::/7 , fe80::/10 , fec0::/10 , ff00::/8 , 2002::/24 , 2002:a00::/24 , 2002:7f00::/24 , 2002:a9fe::/32 , 2002:ac10::/28 , 2002:c000::/40 , 2002:c000:200::/40 , 2002:c0a8::/32 , 2002:c612::/31 , 2002:c633:6400::/40 , 2002:cb00:7100::/40 , 2002:e000::/20 , 2002:f000::/20 , 2002:ffff:ffff::/48 , 2001::/40 , 2001:0:a00::/40 , 2001:0:7f00::/40 , 2001:0:a9fe::/48 , 2001:0:ac10::/44 , 2001:0:c000::/56 , 2001:0:c000:200::/56 , 2001:0:c0a8::/48 , 2001:0:c612::/47 , 2001:0:c633:6400::/56 , 2001:0:cb00:7100::/56 , 2001:0:e000::/36 , 2001:0:f000::/36 , 2001:0:ffff:ffff::/64})","Only traffic that contains source or destination Bogons. Bogons are defined as private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry (RIR) by the Internet Assigned Numbers Authority."

"TRUE","Traffic//!Bogon (external traffic)","!(ip.src in {0.0.0.0/8 , 10.0.0.0/8 , 100.64.0.0/10 , 127.0.0.0/8 , 127.0.53.53 , 169.254.0.0/16 , 172.16.0.0/12 , 192.0.0.0/24 , 192.0.2.0/24 , 192.168.0.0/16 , 198.18.0.0/15 , 198.51.100.0/24 , 203.0.113.0/24 , 224.0.0.0/4 , 240.0.0.0/4 , 255.255.255.255/32} or ipv6.src in {::/128 , ::1/128 , ::ffff:0:0/96 , ::/96 , 100::/64 , 2001:10::/28 , 2001:db8::/32 , fc00::/7 , fe80::/10 , fec0::/10 , ff00::/8 , 2002::/24 , 2002:a00::/24 , 2002:7f00::/24 , 2002:a9fe::/32 , 2002:ac10::/28 , 2002:c000::/40 , 2002:c000:200::/40 , 2002:c0a8::/32 , 2002:c612::/31 , 2002:c633:6400::/40 , 2002:cb00:7100::/40 , 2002:e000::/20 , 2002:f000::/20 , 2002:ffff:ffff::/48 , 2001::/40 , 2001:0:a00::/40 , 2001:0:7f00::/40 , 2001:0:a9fe::/48 , 2001:0:ac10::/44 , 2001:0:c000::/56 , 2001:0:c000:200::/56 , 2001:0:c0a8::/48 , 2001:0:c612::/47 , 2001:0:c633:6400::/56 , 2001:0:cb00:7100::/56 , 2001:0:e000::/36 , 2001:0:f000::/36 , 2001:0:ffff:ffff::/64} or ip.dst in {0.0.0.0/8 , 10.0.0.0/8 , 100.64.0.0/10 , 127.0.0.0/8 , 127.0.53.53 , 169.254.0.0/16 , 172.16.0.0/12 , 192.0.0.0/24 , 192.0.2.0/24 , 192.168.0.0/16 , 198.18.0.0/15 , 198.51.100.0/24 , 203.0.113.0/24 , 224.0.0.0/4 , 240.0.0.0/4 , 255.255.255.255/32} or ipv6.dst in {::/128 , ::1/128 , ::ffff:0:0/96 , ::/96 , 100::/64 , 2001:10::/28 , 2001:db8::/32 , fc00::/7 , fe80::/10 , fec0::/10 , ff00::/8 , 2002::/24 , 2002:a00::/24 , 2002:7f00::/24 , 2002:a9fe::/32 , 2002:ac10::/28 , 2002:c000::/40 , 2002:c000:200::/40 , 2002:c0a8::/32 , 2002:c612::/31 , 2002:c633:6400::/40 , 2002:cb00:7100::/40 , 2002:e000::/20 , 2002:f000::/20 , 2002:ffff:ffff::/48 , 2001::/40 , 2001:0:a00::/40 , 2001:0:7f00::/40 , 2001:0:a9fe::/48 , 2001:0:ac10::/44 , 2001:0:c000::/56 , 2001:0:c000:200::/56 , 2001:0:c0a8::/48 , 2001:0:c612::/47 , 2001:0:c633:6400::/56 , 2001:0:cb00:7100::/56 , 2001:0:e000::/36 , 2001:0:f000::/36 , 2001:0:ffff:ffff::/64})","All Traffic that has no source or destination Bogons. Bogons are defined as private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry (RIR) by the Internet Assigned Numbers Authority."

"TRUE","Traffic//Certificates//Self Signed Certs","x509af.serialNumber < 2 ","Display Self Signed Certs"

"TRUE","Traffic//Certificates//Show Frames with Certificates","tls.handshake.certificates or pkcs12 or x509af or x509ce or x509if or x509sat or ocsp","Show frames with certificates"

"TRUE","Traffic//DCDiscovery","udp.port == 389 or (dns.qry.type == 33 and frame[1:] contains \x22_ldap\x22)","Displays frames associated with the Netlogon DSGETDC (DCDiscovery) process"

"TRUE","Traffic//DNS+DoT","dns or tcp.port in {53,853} or udp.port in {53,853}","DNS and DNS over TLS traffic"

"TRUE","Traffic//Errors in DNS, HTTP and SMB","dns.flags.rcode > 0 or\x0ahttp.response.code > 399 or smb.nt_status > 0 or\x0asmb2.nt_status > 0","Show me DNS or HTTP or SMB errors"

"TRUE","Traffic//Ethernet only","eth.src == ff:ff:ff:ff:ff:ff or eth.dst == ff:ff:ff:ff:ff:ff","Show only ethernet traffic"

"TRUE","Traffic//Follow current Stream","tcp.stream == ${tcp.stream}","Follows the TCP stream of the selected TCP frame"

"TRUE","Traffic//HTTP//Redirects","http.response.code > 299 and http.response.code < 400","Any HTTP Redirects"

"TRUE","Traffic//ICMP//ICMP","icmp or icmpv6","ICMP"

"TRUE","Traffic//ICMP//ICMP TTL Expired","icmp.type == 11 or icmpv6.type == 11","ICMP Time to live expired notification"

"TRUE","Traffic//ICMP//PING","icmp.type in {0,8} or icmpv6.type in {0,8}","Show ICMP Echo Requests and Replies"

"TRUE","Traffic//ICMP//Redirect","icmp.type == 5 or icmpv6.type == 5","Any ICMP Redirects"

"TRUE","Traffic//ICMP//Routing","icmp.type in {9,10} or icmpv6.type in {9,10}",""

"TRUE","Traffic//ICMP//Unassigned, Deprecated, Expermental, Security ICMP traffic","icmp.type in {1,2,6}  or (icmp.type >= 15 and icmp.type <= 39) or icmp.type == 41 or (icmp.type >= 44 and icmp.type <= 254) or icmpv6.type in {1,2,6}  or (icmpv6.type >= 15 and icmpv6.type <= 39) or icmpv6.type == 41 or (icmpv6.type >= 44 and icmpv6.type <= 254)",""

"TRUE","Traffic//Latency//DNS > 400ms","dns.time > .4","Any DNS responses that are greater than .4 seconds"

"TRUE","Traffic//Latency//frame delta > 250ms","frame.time_delta_displayed >= .250","Any packets with greater than .25 second delta times"

"TRUE","Traffic//Latency//frame delta > 500ms","frame.time_delta_displayed >= .500","Any packets with greater than .5 second delta times"

"TRUE","Traffic//Latency//frame delta > 750ms","frame.time_delta_displayed >= .750","Any packets with greater than .75 second delta times"

"TRUE","Traffic//Latency//HTTP > 400ms","http.time > .4","Any HTTP responses that are greater than .4 seconds"
"TRUE","Traffic//Latency//Inititial Round Trip Time > 400ms","tcp.analysis.initial_rtt > .4","Any initial TCP RTT that are greater than .4 seconds"
"TRUE","Traffic//Latency//SMB > 400ms","smb.time >.4 or smb2.time > .4","Any SMB responses that are greater than .4 seconds"
"TRUE","Traffic//Latency//TCP Latency > 400ms","tcp.time_delta > .4","Any TCP responses that are greater than .4 seconds"
"TRUE","Traffic//Malformed//SYN-noMSS","tcp.flags.syn == 1 and !tcp.options.mss_val","Any TCP SYN packets with no MSS"

"TRUE","Traffic//Malformed//TCP and ICMP","tcp && icmp","Show me illegal packets that are ICMP in TCP"

"TRUE","Traffic//Malformed//TCP SYN","((tcp.flags.reset == 1) and (tcp.seq == 1)) and (tcp.ack == 1)","Show me all packets with illegal TCP SYN flags"

"TRUE","Traffic//Net Scaler Reset Code","tcp.flags.reset == 1 and tcp.window_size_value >= 8146 and tcp.window_size_value <= 10042","Citrix Netscaler reset code in TCP window field (https://support.citrix.com/article/CTX200852)"

"TRUE","Traffic//RDP","(tcp.port == 3389) or (udp.port == 3389) ","Display only RDP traffic"

"TRUE","Traffic//!RDP","!(tcp.port == 3389) or !(udp.port == 3389) ","Filter out all RDP traffic"

"TRUE","Traffic//Security//Clear Text//Logins","frame matches \x22(?i)(login)\x22","Show me all packets that contain the clear text 'login'"

"TRUE","Traffic//Security//Clear Text//Passwords","frame[1:] matches \x22(?i)(passwd|pass|password) and !(passive|passwordreset)\x22","Show me all packets that contain the clear text 'password'"

"TRUE","Traffic//Security//Fiddler","frame[1:] contains \x22(?i)Fiddler\x22","Displays frames that have a marker for Fiddler"

"TRUE","Traffic//Security//Suspicious","(ftp.request.command == \x22USER\x22 and tcp.len>50) or frame[1:] matches \x22(?i)join #\x22 or tftp or irc or bittorrent or smb2.cmd==3 or smb2.cmd==5 or smb2.cmd==3 or smb2.cmd==5 or frame[1:] contains \x22(?i)nessus\x22 or frame[1:] contains \x22Nmap\x22 or frame[1:] contains \x22Fiddler\x22 or frame[1:] contains \x22.exe\x22 or (frame[1:] contains \x22.com\x22 and !tcp.port == 443) or frame[1:] contains \x22.doc\x22 or frame[1:] contains \x22.xls\x22 or frame[1:] contains \x22.ppt\x22 or (frame[1:] contains \x22.msi\x22 and !frame[1:] contains \x22.msidentity\x22) or frame[1:] contains \x22.rar\x22 or frame[1:] contains \x22.zip\x22 or frame[1:] contains \x22.vbs\x22 or frame[1:] contains \x22.ps1\x22 or frame[1:] contains \x22office\x22 or frame matches \x22join #\x22 or (ftp.request.command==\x22USER\x22 && tcp.len>50)","Suspicious traffic based on SMB Command, User Agent string and other markers"

"TRUE","Traffic//Security//Top 10 Cyberattacking countries (2022 data)","ip.geoip.country in {China, \x22United States\x22 , Brazil , India , Germany , Vietnam , Thailand , Russia , Indonesia , Netherlands}","(2022 data) Top 10 countries originating cyberattacks account for ~60%+ of attacks.  China , United States , Brazil , India , Germany , Vietnam , Thailand , Russia , Indonesia , Netherlands"

"TRUE","Traffic//Security//Top 10 Cyberattacking countries sans US (2022 data)","ip.geoip.country in {China, Brazil , India , Germany , Vietnam , Thailand , Russia , Indonesia , Netherlands}","(2022 data) Top 10 countries originating cyberattacks account for ~40%+ of attacks.  China , Brazil , India , Germany , Vietnam , Thailand , Russia , Indonesia , Netherlands"

"TRUE","Traffic//Security//Unassigned, Deprecated, Expermental, Security ICMP traffic","icmp.type == 1 or icmp.type == 2 or icmp.type == 6  or (icmp.type >= 15 and icmp.type <= 39) or icmp.type == 41 or (icmp.type >= 44 and icmp.type <= 254) or icmpv6.type == 1 or icmpv6.type == 2 or icmpv6.type == 6  or (icmpv6.type >= 15 and icmpv6.type <= 39) or icmpv6.type == 41 or (icmpv6.type >= 44 and icmpv6.type <= 254)",""

"TRUE","Traffic//TCP//Retransmits","(tcp.analysis.retransmission or tcp.analysis.zero_window) and !(tcp.port == 3389 or udp.port == 3389)","TCP Retransmission"

"TRUE","Traffic//TCP//SYN","tcp.flags.syn == 1","Show me all the TCP SYNs"

"TRUE","Traffic//TCP//TCP Conversation completeness//Finished conversations","tcp.completeness in {31 , 47 , 63}","TCP Conversation Completeness - TCP conversations are said to be complete when they have both opening and closing handshakes, independently of any data transfer. However, we might be interested in identifying complete conversations with some data sent, and we are using the following bit values to build a filter value on the tcp.completeness field : 1 : SYN\x0a2 : SYN-ACK\x0a4 : ACK\x0a8 : DATA\x0a16 : FIN\x0a32 : RST\x0aFor example, a conversation containing only a three-way handshake will be found with the filter 'tcp.completeness==7' (1+2+4) while a complete conversation with data transfer will be found with a longer filter as closing a connection can be associated with FIN or RST packets, or even both : 'tcp.completeness==31 or tcp.completeness==47 or tcp.completeness==63'\x0a\x0a "

"TRUE","Traffic//TCP//TCP Analysis Flags","tcp.analysis.flags","Quick check on TCP Analysis Flags"

"TRUE","Traffic//TCP//TCP Flags","tcp.flags in {0x2,0x4,0xc2,0x12,0x52,0x14}","DIsplay all frames where a TCP Flag is set"

"TRUE","Traffic//TLS//Bad TLS","tls.handshake.version < 0x0303","TLS lower that TLS 1.2"

"TRUE","Traffic//TLS//HTTPS","tcp.port == 443","All tcp port 443 traffic"
"TRUE","Traffic//TLS//Malformed","tls.malformed.buffer_too_small or tls.malformed.trailing_data or tls.malformed.vector_length or tls.record.length.invalid",""

"TRUE","Traffic//TLS//Target Name","tls.handshake.extensions_server_name or dns.qry.name","Display TLS target name with DNS name query included"

"TRUE","Traffic//TLS//TLS Alerts","(tls.record.content_type == 21) && (tls.record.length < 26)","TLS Alerts -- remember a tls.record.length = 26 just a normal termination"

"TRUE","Traffic//TLS//TLS failed with no Server Hello","tcp.stream and !tls.handshake.type == 2 and tls.handshake.type == 1","Identify failed TLS streams that did receive a Server Hello"

"TRUE","Traffic//TLS//TLS HS","tls.handshake.type >= 1 ","Building the TLS tunnel Handshake"

"TRUE","Traffic//TLS//Unencrypted HTTP over TLS port","http.tls_port","Unencrypted HTTP traffic over TLS port"

"TRUE","Traffic//TLS//Web Proxy","http.request.method == \x22CONNECT\x22 or http.proxy_authenticate or http.proxy_authorization or http.proxy_connect_host","FIlter for Internet proxy CONNECT request"

"TRUE","Traffic//TTL <= 64 or > 128","ip.ttl <= 64 or ip.ttl > 128 or ipv6.hlim <= 64 or ipv6.hlim > 128","Check for TTL < 64 and > 128  Looking for intermediate networking devices by observing the time to live for IP frames. Windows TTL starts at 128 and non-windows machines or devices "

"TRUE","Traffic//WinRM","tcp.port in {5985 , 5986}","Windown Remove Management (WinRM)"

"TRUE","Show Frames with Packet Comments","pkt_comment","Packets with Comments"

"TRUE","Follow Stream","tcp.stream == ${tcp.stream}","Follow TCP stream of currently selected frame"



# Packet list column format
# Each pair of strings consists of a column title and its format

gui.column.format: 
	
	"#", "%m",
	
	"PID", "%Cus:frame.comment:0:R",
	
	"⌚Δ", "%Tt",
	
	"ByIF", "%Cus:tcp.analysis.bytes_in_flight:0:R",
	
	"RTT", "%Cus:tcp.analysis.ack_rtt:0:R",
	
	"⌚", "%t",
	
	"Interface", "%Cus:frame.interface_description:0:R",
	
	"Source Host/IP , City,  Country , ASN , Owner", "%Cus:ip.src_host or ip.geoip.src_summary or ipv6.src_host or ipv6.geoip.src_summary:0:R",
	
	"Local Interface Ingress MFG", "%Cus:eth.src.oui_resolved or eth.src:0:R",
	
	"Destination Host/IP , City , Country, ASN , Owner", "%Cus:ip.dst_host or ip.geoip.dst_summary or ipv6.dst_host or ipv6.geoip.dst_summary:0:R",
	
	"Local Interface Egress MFG", "%Cus:eth.dst.oui_resolved or eth.dst:0:R",
	
	"SPort", "%Cus:tcp.srcport or udp.srcport:0:R",
	
	"DPort", "%Cus:tcp.dstport or udp.dstport:0:R",
	
	"Auth", "%Cus:kerberos or ntlmssp or radius or ldap.authentication or imap.request.username or mapi.EcDoConnect.name:0:R",
	
	"Username", "%Cus:radius.User_Name or ntlmssp.auth.username or imap.request.username or mapi.EcDoConnect.name or kerberos.CNameString or ntlmssp.auth.domain or ntlmssp.auth.hostname:0:R",
	
	"Kerberos Principle", "%Cus:kerberos.SNameString or kerberos.CNameString:0:R",
	
	"# Cert(s) + Size", "%Cus:tls.handshake.certificate_length:0:R",
	
	"CRL", "%Cus:x509ce.uniformResourceIdentifier:0:R",
	
	"LDAP assertion / SNI / URI / HTTP / Cert", "%Cus:tls.handshake.extensions_server_name or http.request or http.request.uri or http.request.line or dns.qry.name or ldap.assertionValue or x509sat.printableString:0:R",
	
	"Length", "%L",
	
	"TLS Protocols", "%Cus:tls.handshake.extensions.supported_version or tls.record.version or tls.handshake.version:0:R",
	
	"Protocol", "%Cus:frame.protocols:0:R",
	
	"TCP Stream # & completeness", "%Cus:tcp.stream or tcp.completeness:0:R",
	
	"HTTP version", "%Cus:tls.handshake.extensions_alpn_str:0:R",
	
	"TTL", "%Cus:ip.ttl or ipv6.hlim:0:R",
	
	"Window", "%Cus:tcp.window_size_value:0:R",
	
	"Expert", "%Cus:_ws.expert.message:0:R",
	
	"Info", "%i"
	
# Wireshark customer macros
macros
"https","tcp.port == 443"

"auth","kerberos or ntlmssp or radius or ldap.authentication or udp.port in {88,1645,1646,1812,1813} or tcp.port ==88 or imap.request.username or mapi.EcDoConnect.name or kerberos.CNameString or tls.handshake.extensions_server_name in {\x22autologon.microsoftazuread-sso.com\x22 , \x22adnotifications.windowsazure.com\x22 , \x22login.microsoftonline.com\x22 , \x22autologon.microsoftazuread-sso.us\x22 , \x22adnotifications.windowsazure.us\x22 , \x22logon.microsoftonline.us\x22 , \x22device.login.microsoftonline.com\x22} or (tls.handshake.type == 11 and !tcp.srcport == 443) or http.proxy_authenticate"

"bogon","(ip.src in {0.0.0.0/8 , 10.0.0.0/8 , 100.64.0.0/10 , 127.0.0.0/8 , 127.0.53.53 , 169.254.0.0/16 , 172.16.0.0/12 , 192.0.0.0/24 , 192.0.2.0/24 , 192.168.0.0/16 , 198.18.0.0/15 , 198.51.100.0/24 , 203.0.113.0/24 , 224.0.0.0/4 , 240.0.0.0/4 , 255.255.255.255/32} or ipv6.src in {::/128 , ::1/128 , ::ffff:0:0/96 , ::/96 , 100::/64 , 2001:10::/28 , 2001:db8::/32 , fc00::/7 , fe80::/10 , fec0::/10 , ff00::/8 , 2002::/24 , 2002:a00::/24 , 2002:7f00::/24 , 2002:a9fe::/32 , 2002:ac10::/28 , 2002:c000::/40 , 2002:c000:200::/40 , 2002:c0a8::/32 , 2002:c612::/31 , 2002:c633:6400::/40 , 2002:cb00:7100::/40 , 2002:e000::/20 , 2002:f000::/20 , 2002:ffff:ffff::/48 , 2001::/40 , 2001:0:a00::/40 , 2001:0:7f00::/40 , 2001:0:a9fe::/48 , 2001:0:ac10::/44 , 2001:0:c000::/56 , 2001:0:c000:200::/56 , 2001:0:c0a8::/48 , 2001:0:c612::/47 , 2001:0:c633:6400::/56 , 2001:0:cb00:7100::/56 , 2001:0:e000::/36 , 2001:0:f000::/36 , 2001:0:ffff:ffff::/64} or ip.dst in {0.0.0.0/8 , 10.0.0.0/8 , 100.64.0.0/10 , 127.0.0.0/8 , 127.0.53.53 , 169.254.0.0/16 , 172.16.0.0/12 , 192.0.0.0/24 , 192.0.2.0/24 , 192.168.0.0/16 , 198.18.0.0/15 , 198.51.100.0/24 , 203.0.113.0/24 , 224.0.0.0/4 , 240.0.0.0/4 , 255.255.255.255/32} or ipv6.dst in {::/128 , ::1/128 , ::ffff:0:0/96 , ::/96 , 100::/64 , 2001:10::/28 , 2001:db8::/32 , fc00::/7 , fe80::/10 , fec0::/10 , ff00::/8 , 2002::/24 , 2002:a00::/24 , 2002:7f00::/24 , 2002:a9fe::/32 , 2002:ac10::/28 , 2002:c000::/40 , 2002:c000:200::/40 , 2002:c0a8::/32 , 2002:c612::/31 , 2002:c633:6400::/40 , 2002:cb00:7100::/40 , 2002:e000::/20 , 2002:f000::/20 , 2002:ffff:ffff::/48 , 2001::/40 , 2001:0:a00::/40 , 2001:0:7f00::/40 , 2001:0:a9fe::/48 , 2001:0:ac10::/44 , 2001:0:c000::/56 , 2001:0:c000:200::/56 , 2001:0:c0a8::/48 , 2001:0:c612::/47 , 2001:0:c633:6400::/56 , 2001:0:cb00:7100::/56 , 2001:0:e000::/36 , 2001:0:f000::/36 , 2001:0:ffff:ffff::/64})"
