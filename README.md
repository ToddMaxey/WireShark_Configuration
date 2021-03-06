# WireShark Configuration

This is my personal Wireshark configuration. This aids me in troubleshooting by adding new columns and filter buttons to help identify networking and or machine configuration issues. 

#Filter Buttons and Column settings

Filter Buttons

"Auth//All","kerberos or ntlmssp or radius or ldap.authentication or udp.port == 1812 or udp.port == 1813 or udp.port == 1645 or udp.port == 1646 or tcp.port ==88  or udp.port == 88 or imap.request.username or mapi.EcDoConnect.name or kerberos.CNameString or tls.handshake.extensions_server_name == \x22autologon.microsoftazuread-sso.com\x22 or tls.handshake.extensions_server_name == \x22adnotifications.windowsazure.com\x22 or tls.handshake.extensions_server_name == \x22logon.microsoftonline.com\x22 or tls.handshake.extensions_server_name == \x22autologon.microsoftazuread-sso.us\x22 or tls.handshake.extensions_server_name == \x22adnotifications.windowsazure.us\x22 or tls.handshake.extensions_server_name == \x22logon.microsoftonline.us\x22 or tls.handshake.extensions_server_name == \x22device.logon.microsoftonline.com\x22 or (tls.handshake.type == 11 and !tcp.srcport == 443) or http.proxy_authenticate","Filter on Kerberos, NTLM, Radius auth or Cert Auth"

"Auth//External destination Auth","!(ip.src == 0.0.0.0/8 or ip.src == 10.0.0.0/8 or ip.src == 100.64.0.0/10 or ip.src == 127.0.0.0/8 or ip.src == 127.0.53.53 or ip.src == 169.254.0.0/16 or ip.src == 172.16.0.0/12 or ip.src == 192.0.0.0/24 or ip.src == 192.0.2.0/24 or ip.src == 192.168.0.0/16 or ip.src == 198.18.0.0/15 or ip.src == 198.51.100.0/24 or ip.src == 203.0.113.0/24 or ip.src == 224.0.0.0/4 or ip.src == 240.0.0.0/4 or ip.src == 255.255.255.255/32 or ipv6.src == ::/128 or ipv6.src == ::1/128 or ipv6.src == ::ffff:0:0/96 or ipv6.src == ::/96 or ipv6.src == 100::/64 or ipv6.src == 2001:10::/28 or ipv6.src == 2001:db8::/32 or ipv6.src == fc00::/7 or ipv6.src == fe80::/10 or ipv6.src == fec0::/10 or ipv6.src == ff00::/8 or ipv6.src == 2002::/24 or ipv6.src == 2002:a00::/24 or ipv6.src == 2002:7f00::/24 or ipv6.src == 2002:a9fe::/32 or ipv6.src == 2002:ac10::/28 or ipv6.src == 2002:c000::/40 or ipv6.src == 2002:c000:200::/40 or ipv6.src == 2002:c0a8::/32 or ipv6.src == 2002:c612::/31 or ipv6.src == 2002:c633:6400::/40 or ipv6.src == 2002:cb00:7100::/40 or ipv6.src == 2002:e000::/20 or ipv6.src == 2002:f000::/20 or ipv6.src == 2002:ffff:ffff::/48 or ipv6.src == 2001::/40 or ipv6.src == 2001:0:a00::/40 or ipv6.src == 2001:0:7f00::/40 or ipv6.src == 2001:0:a9fe::/48 or ipv6.src == 2001:0:ac10::/44 or ipv6.src == 2001:0:c000::/56 or ipv6.src == 2001:0:c000:200::/56 or ipv6.src == 2001:0:c0a8::/48 or ipv6.src == 2001:0:c612::/47 or ipv6.src == 2001:0:c633:6400::/56 or ipv6.src == 2001:0:cb00:7100::/56 or ipv6.src == 2001:0:e000::/36 or ipv6.src == 2001:0:f000::/36 or ipv6.src == 2001:0:ffff:ffff::/64 or ip.dst == 0.0.0.0/8 or ip.dst == 10.0.0.0/8 or ip.dst == 100.64.0.0/10 or ip.dst == 127.0.0.0/8 or ip.dst == 127.0.53.53 or ip.dst == 169.254.0.0/16 or ip.dst == 172.16.0.0/12 or ip.dst == 192.0.0.0/24 or ip.dst == 192.0.2.0/24 or ip.dst == 192.168.0.0/16 or ip.dst == 198.18.0.0/15 or ip.dst == 198.51.100.0/24 or ip.dst == 203.0.113.0/24 or ip.dst == 224.0.0.0/4 or ip.dst == 240.0.0.0/4 or ip.dst == 255.255.255.255/32 or ipv6.dst == ::/128 or ipv6.dst == ::1/128 or ipv6.dst == ::ffff:0:0/96 or ipv6.dst == ::/96 or ipv6.dst == 100::/64 or ipv6.dst == 2001:10::/28 or ipv6.dst == 2001:db8::/32 or ipv6.dst == fc00::/7 or ipv6.dst == fe80::/10 or ipv6.dst == fec0::/10 or ipv6.dst == ff00::/8 or ipv6.dst == 2002::/24 or ipv6.dst == 2002:a00::/24 or ipv6.dst == 2002:7f00::/24 or ipv6.dst == 2002:a9fe::/32 or ipv6.dst == 2002:ac10::/28 or ipv6.dst == 2002:c000::/40 or ipv6.dst == 2002:c000:200::/40 or ipv6.dst == 2002:c0a8::/32 or ipv6.dst == 2002:c612::/31 or ipv6.dst == 2002:c633:6400::/40 or ipv6.dst == 2002:cb00:7100::/40 or ipv6.dst == 2002:e000::/20 or ipv6.dst == 2002:f000::/20 or ipv6.dst == 2002:ffff:ffff::/48 or ipv6.dst == 2001::/40 or ipv6.dst == 2001:0:a00::/40 or ipv6.dst == 2001:0:7f00::/40 or ipv6.dst == 2001:0:a9fe::/48 or ipv6.dst == 2001:0:ac10::/44 or ipv6.dst == 2001:0:c000::/56 or ipv6.dst == 2001:0:c000:200::/56 or ipv6.dst == 2001:0:c0a8::/48 or ipv6.dst == 2001:0:c612::/47 or ipv6.dst == 2001:0:c633:6400::/56 or ipv6.dst == 2001:0:cb00:7100::/56 or ipv6.dst == 2001:0:e000::/36 or ipv6.dst == 2001:0:f000::/36 or ipv6.dst == 2001:0:ffff:ffff::/64) and (kerberos or ntlmssp or radius or ldap.authentication or udp.port == 1812 or udp.port == 1813 or udp.port == 1645 or udp.port == 1646 or tcp.port ==88 or udp.port == 88 or imap.request.username or mapi.EcDoConnect.name or kerberos.CNameString or tls.handshake.extensions_server_name == \x22autologon.microsoftazuread-sso.com\x22 or tls.handshake.extensions_server_name == \x22adnotifications.windowsazure.com\x22 or tls.handshake.extensions_server_name == \x22logon.microsoftonline.com\x22 or tls.handshake.extensions_server_name == \x22autologon.microsoftazuread-sso.us\x22 or tls.handshake.extensions_server_name == \x22adnotifications.windowsazure.us\x22 or tls.handshake.extensions_server_name == \x22logon.microsoftonline.us\x22 or tls.handshake.extensions_server_name == \x22device.logon.microsoftonline.com\x22 or http.proxy_authenticate)","External/Internet destination Authenication"

"Auth//On premise Auth","(ip.src == 0.0.0.0/8 or ip.src == 10.0.0.0/8 or ip.src == 100.64.0.0/10 or ip.src == 127.0.0.0/8 or ip.src == 127.0.53.53 or ip.src == 169.254.0.0/16 or ip.src == 172.16.0.0/12 or ip.src == 192.0.0.0/24 or ip.src == 192.0.2.0/24 or ip.src == 192.168.0.0/16 or ip.src == 198.18.0.0/15 or ip.src == 198.51.100.0/24 or ip.src == 203.0.113.0/24 or ip.src == 224.0.0.0/4 or ip.src == 240.0.0.0/4 or ip.src == 255.255.255.255/32 or ipv6.src == ::/128 or ipv6.src == ::1/128 or ipv6.src == ::ffff:0:0/96 or ipv6.src == ::/96 or ipv6.src == 100::/64 or ipv6.src == 2001:10::/28 or ipv6.src == 2001:db8::/32 or ipv6.src == fc00::/7 or ipv6.src == fe80::/10 or ipv6.src == fec0::/10 or ipv6.src == ff00::/8 or ipv6.src == 2002::/24 or ipv6.src == 2002:a00::/24 or ipv6.src == 2002:7f00::/24 or ipv6.src == 2002:a9fe::/32 or ipv6.src == 2002:ac10::/28 or ipv6.src == 2002:c000::/40 or ipv6.src == 2002:c000:200::/40 or ipv6.src == 2002:c0a8::/32 or ipv6.src == 2002:c612::/31 or ipv6.src == 2002:c633:6400::/40 or ipv6.src == 2002:cb00:7100::/40 or ipv6.src == 2002:e000::/20 or ipv6.src == 2002:f000::/20 or ipv6.src == 2002:ffff:ffff::/48 or ipv6.src == 2001::/40 or ipv6.src == 2001:0:a00::/40 or ipv6.src == 2001:0:7f00::/40 or ipv6.src == 2001:0:a9fe::/48 or ipv6.src == 2001:0:ac10::/44 or ipv6.src == 2001:0:c000::/56 or ipv6.src == 2001:0:c000:200::/56 or ipv6.src == 2001:0:c0a8::/48 or ipv6.src == 2001:0:c612::/47 or ipv6.src == 2001:0:c633:6400::/56 or ipv6.src == 2001:0:cb00:7100::/56 or ipv6.src == 2001:0:e000::/36 or ipv6.src == 2001:0:f000::/36 or ipv6.src == 2001:0:ffff:ffff::/64 or ip.dst == 0.0.0.0/8 or ip.dst == 10.0.0.0/8 or ip.dst == 100.64.0.0/10 or ip.dst == 127.0.0.0/8 or ip.dst == 127.0.53.53 or ip.dst == 169.254.0.0/16 or ip.dst == 172.16.0.0/12 or ip.dst == 192.0.0.0/24 or ip.dst == 192.0.2.0/24 or ip.dst == 192.168.0.0/16 or ip.dst == 198.18.0.0/15 or ip.dst == 198.51.100.0/24 or ip.dst == 203.0.113.0/24 or ip.dst == 224.0.0.0/4 or ip.dst == 240.0.0.0/4 or ip.dst == 255.255.255.255/32 or ipv6.dst == ::/128 or ipv6.dst == ::1/128 or ipv6.dst == ::ffff:0:0/96 or ipv6.dst == ::/96 or ipv6.dst == 100::/64 or ipv6.dst == 2001:10::/28 or ipv6.dst == 2001:db8::/32 or ipv6.dst == fc00::/7 or ipv6.dst == fe80::/10 or ipv6.dst == fec0::/10 or ipv6.dst == ff00::/8 or ipv6.dst == 2002::/24 or ipv6.dst == 2002:a00::/24 or ipv6.dst == 2002:7f00::/24 or ipv6.dst == 2002:a9fe::/32 or ipv6.dst == 2002:ac10::/28 or ipv6.dst == 2002:c000::/40 or ipv6.dst == 2002:c000:200::/40 or ipv6.dst == 2002:c0a8::/32 or ipv6.dst == 2002:c612::/31 or ipv6.dst == 2002:c633:6400::/40 or ipv6.dst == 2002:cb00:7100::/40 or ipv6.dst == 2002:e000::/20 or ipv6.dst == 2002:f000::/20 or ipv6.dst == 2002:ffff:ffff::/48 or ipv6.dst == 2001::/40 or ipv6.dst == 2001:0:a00::/40 or ipv6.dst == 2001:0:7f00::/40 or ipv6.dst == 2001:0:a9fe::/48 or ipv6.dst == 2001:0:ac10::/44 or ipv6.dst == 2001:0:c000::/56 or ipv6.dst == 2001:0:c000:200::/56 or ipv6.dst == 2001:0:c0a8::/48 or ipv6.dst == 2001:0:c612::/47 or ipv6.dst == 2001:0:c633:6400::/56 or ipv6.dst == 2001:0:cb00:7100::/56 or ipv6.dst == 2001:0:e000::/36 or ipv6.dst == 2001:0:f000::/36 or ipv6.dst == 2001:0:ffff:ffff::/64) and (kerberos or ntlmssp or radius or ldap.authentication or udp.port == 1812 or udp.port == 1813 or udp.port == 1645 or udp.port == 1646 or tcp.port ==88 or udp.port == 88 or imap.request.username or mapi.EcDoConnect.name or kerberos.CNameString or tls.handshake.extensions_server_name == \x22autologon.microsoftazuread-sso.com\x22 or tls.handshake.extensions_server_name == \x22adnotifications.windowsazure.com\x22 or tls.handshake.extensions_server_name == \x22logon.microsoftonline.com\x22 or tls.handshake.extensions_server_name == \x22autologon.microsoftazuread-sso.us\x22 or tls.handshake.extensions_server_name == \x22adnotifications.windowsazure.us\x22 or tls.handshake.extensions_server_name == \x22logon.microsoftonline.us\x22 or tls.handshake.extensions_server_name == \x22device.logon.microsoftonline.com\x22 or http.proxy_authenticate)","On permise (Bogon source and destination) Authenication"

"Auth//Username","radius.User_Name or ntlmssp.auth.username or imap.request.username or mapi.EcDoConnect.name or kerberos.CNameString or (tls.handshake.type == 13 and x509sat.DirectoryString == 1 and !tls.handshake.type == 2)",""

"Certificates//Self Signed Certs","x509af.serialNumber < 2 ","Display Self Signed Certs"

"Certificates//Show Frames with Certificates","tls.handshake.certificates or pkcs12 or x509af or x509ce or x509if or x509sat or ocsp",""

"Show Frames with Packet Comments","pkt_comment","Packets with Comments"

"Security//Clear Text//Logins","frame matches \x22(?i)(login)\x22","Show me all packets that contain the clear text 'login'"

"Security//Clear text//Passwords","frame[1:] matches \x22(?i)(passwd|pass|password)\x22","Show me all packets that contain the clear text 'password'"

"Security//Fiddler","frame[1:] contains \x22(?i)Fiddler\x22","Displays frames that have a marker for Fiddler"

"Security//Suspicious","(ftp.request.command == \x22USER\x22 and tcp.len>50) or frame[1:] matches \x22(?i)join #\x22 or tftp or irc or bittorrent or smb2.cmd==3 or smb2.cmd==5 or smb2.cmd==3 or smb2.cmd==5 or frame[1:] contains \x22(?i)nessus\x22 or frame[1:] contains \x22Nmap\x22 or frame[1:] contains \x22Fiddler\x22 or frame[1:] contains \x22.exe\x22 or (frame[1:] contains \x22.com\x22 and !tcp.port == 443) or frame[1:] contains \x22.doc\x22 or frame[1:] contains \x22.xls\x22 or frame[1:] contains \x22.ppt\x22 or (frame[1:] contains \x22.msi\x22 and !frame[1:] contains \x22.msidentity\x22) or frame[1:] contains \x22.rar\x22 or frame[1:] contains \x22.zip\x22 or frame[1:] contains \x22.vbs\x22 or frame[1:] contains \x22.ps1\x22 or frame[1:] contains \x22office\x22 or frame matches \x22join #\x22 or (ftp.request.command==\x22USER\x22 && tcp.len>50)","Suspicious traffic based on SMB Command, User Agent string and other markers"

"TLS//Bad TLS","tls.handshake.version < 0x0303","TLS lower that TLS 1.2"

"TLS//HTTPS","tcp.port == 443","All tcp port 443 traffic"

"TLS//Target Name","tls.handshake.extensions_server_name or dns.qry.name","Display TLS target name with DNS name query included"

"TLS//TLS Alerts","(tls.record.content_type == 21) && (tls.record.length < 26)","TLS Alerts -- remember a tls.record.length = 26 just a normal termination"

"TLS//TLS HS","tls.handshake.type >= 1 ","Building the TLS tunnel Handshake"

"TLS//Web Proxy","http.request.method == \x22CONNECT\x22 or http.proxy_authenticate or http.proxy_authorization or http.proxy_connect_host","FIlter for Internet proxy CONNECT request"

"Traffic//Bogon ONLY","\x0a!(icmp.type == 11) and (ip.src == 0.0.0.0/8 or ip.src == 10.0.0.0/8 or ip.src == 100.64.0.0/10 or ip.src == 127.0.0.0/8 or ip.src == 127.0.53.53 or ip.src == 169.254.0.0/16 or ip.src == 172.16.0.0/12 or ip.src == 192.0.0.0/24 or ip.src == 192.0.2.0/24 or ip.src == 192.168.0.0/16 or ip.src == 198.18.0.0/15 or ip.src == 198.51.100.0/24 or ip.src == 203.0.113.0/24 or ip.src == 224.0.0.0/4 or ip.src == 240.0.0.0/4 or ip.src == 255.255.255.255/32 or ipv6.src == ::/128 or ipv6.src == ::1/128 or ipv6.src == ::ffff:0:0/96 or ipv6.src == ::/96 or ipv6.src == 100::/64 or ipv6.src == 2001:10::/28 or ipv6.src == 2001:db8::/32 or ipv6.src == fc00::/7 or ipv6.src == fe80::/10 or ipv6.src == fec0::/10 or ipv6.src == ff00::/8 or ipv6.src == 2002::/24 or ipv6.src == 2002:a00::/24 or ipv6.src == 2002:7f00::/24 or ipv6.src == 2002:a9fe::/32 or ipv6.src == 2002:ac10::/28 or ipv6.src == 2002:c000::/40 or ipv6.src == 2002:c000:200::/40 or ipv6.src == 2002:c0a8::/32 or ipv6.src == 2002:c612::/31 or ipv6.src == 2002:c633:6400::/40 or ipv6.src == 2002:cb00:7100::/40 or ipv6.src == 2002:e000::/20 or ipv6.src == 2002:f000::/20 or ipv6.src == 2002:ffff:ffff::/48 or ipv6.src == 2001::/40 or ipv6.src == 2001:0:a00::/40 or ipv6.src == 2001:0:7f00::/40 or ipv6.src == 2001:0:a9fe::/48 or ipv6.src == 2001:0:ac10::/44 or ipv6.src == 2001:0:c000::/56 or ipv6.src == 2001:0:c000:200::/56 or ipv6.src == 2001:0:c0a8::/48 or ipv6.src == 2001:0:c612::/47 or ipv6.src == 2001:0:c633:6400::/56 or ipv6.src == 2001:0:cb00:7100::/56 or ipv6.src == 2001:0:e000::/36 or ipv6.src == 2001:0:f000::/36 or ipv6.src == 2001:0:ffff:ffff::/64) and (ip.dst == 0.0.0.0/8 or ip.dst == 10.0.0.0/8 or ip.dst == 100.64.0.0/10 or ip.dst == 127.0.0.0/8 or ip.dst == 127.0.53.53 or ip.dst == 169.254.0.0/16 or ip.dst == 172.16.0.0/12 or ip.dst == 192.0.0.0/24 or ip.dst == 192.0.2.0/24 or ip.dst == 192.168.0.0/16 or ip.dst == 198.18.0.0/15 or ip.dst == 198.51.100.0/24 or ip.dst == 203.0.113.0/24 or ip.dst == 224.0.0.0/4 or ip.dst == 240.0.0.0/4 or ip.dst == 255.255.255.255/32 or ipv6.dst == ::/128 or ipv6.dst == ::1/128 or ipv6.dst == ::ffff:0:0/96 or ipv6.dst == ::/96 or ipv6.dst == 100::/64 or ipv6.dst == 2001:10::/28 or ipv6.dst == 2001:db8::/32 or ipv6.dst == fc00::/7 or ipv6.dst == fe80::/10 or ipv6.dst == fec0::/10 or ipv6.dst == ff00::/8 or ipv6.dst == 2002::/24 or ipv6.dst == 2002:a00::/24 or ipv6.dst == 2002:7f00::/24 or ipv6.dst == 2002:a9fe::/32 or ipv6.dst == 2002:ac10::/28 or ipv6.dst == 2002:c000::/40 or ipv6.dst == 2002:c000:200::/40 or ipv6.dst == 2002:c0a8::/32 or ipv6.dst == 2002:c612::/31 or ipv6.dst == 2002:c633:6400::/40 or ipv6.dst == 2002:cb00:7100::/40 or ipv6.dst == 2002:e000::/20 or ipv6.dst == 2002:f000::/20 or ipv6.dst == 2002:ffff:ffff::/48 or ipv6.dst == 2001::/40 or ipv6.dst == 2001:0:a00::/40 or ipv6.dst == 2001:0:7f00::/40 or ipv6.dst == 2001:0:a9fe::/48 or ipv6.dst == 2001:0:ac10::/44 or ipv6.dst == 2001:0:c000::/56 or ipv6.dst == 2001:0:c000:200::/56 or ipv6.dst == 2001:0:c0a8::/48 or ipv6.dst == 2001:0:c612::/47 or ipv6.dst == 2001:0:c633:6400::/56 or ipv6.dst == 2001:0:cb00:7100::/56 or ipv6.dst == 2001:0:e000::/36 or ipv6.dst == 2001:0:f000::/36 or ipv6.dst == 2001:0:ffff:ffff::/64)","Only traffic that contains source or destination Bogons. Bogons are defined as private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry (RIR) by the Internet Assigned Numbers Authority."

"Traffic//!Bogon (external)","!(ip.src == 0.0.0.0/8 or ip.src == 10.0.0.0/8 or ip.src == 100.64.0.0/10 or ip.src == 127.0.0.0/8 or ip.src == 127.0.53.53 or ip.src == 169.254.0.0/16 or ip.src == 172.16.0.0/12 or ip.src == 192.0.0.0/24 or ip.src == 192.0.2.0/24 or ip.src == 192.168.0.0/16 or ip.src == 198.18.0.0/15 or ip.src == 198.51.100.0/24 or ip.src == 203.0.113.0/24 or ip.src == 224.0.0.0/4 or ip.src == 240.0.0.0/4 or ip.src == 255.255.255.255/32 or ipv6.src == ::/128 or ipv6.src == ::1/128 or ipv6.src == ::ffff:0:0/96 or ipv6.src == ::/96 or ipv6.src == 100::/64 or ipv6.src == 2001:10::/28 or ipv6.src == 2001:db8::/32 or ipv6.src == fc00::/7 or ipv6.src == fe80::/10 or ipv6.src == fec0::/10 or ipv6.src == ff00::/8 or ipv6.src == 2002::/24 or ipv6.src == 2002:a00::/24 or ipv6.src == 2002:7f00::/24 or ipv6.src == 2002:a9fe::/32 or ipv6.src == 2002:ac10::/28 or ipv6.src == 2002:c000::/40 or ipv6.src == 2002:c000:200::/40 or ipv6.src == 2002:c0a8::/32 or ipv6.src == 2002:c612::/31 or ipv6.src == 2002:c633:6400::/40 or ipv6.src == 2002:cb00:7100::/40 or ipv6.src == 2002:e000::/20 or ipv6.src == 2002:f000::/20 or ipv6.src == 2002:ffff:ffff::/48 or ipv6.src == 2001::/40 or ipv6.src == 2001:0:a00::/40 or ipv6.src == 2001:0:7f00::/40 or ipv6.src == 2001:0:a9fe::/48 or ipv6.src == 2001:0:ac10::/44 or ipv6.src == 2001:0:c000::/56 or ipv6.src == 2001:0:c000:200::/56 or ipv6.src == 2001:0:c0a8::/48 or ipv6.src == 2001:0:c612::/47 or ipv6.src == 2001:0:c633:6400::/56 or ipv6.src == 2001:0:cb00:7100::/56 or ipv6.src == 2001:0:e000::/36 or ipv6.src == 2001:0:f000::/36 or ipv6.src == 2001:0:ffff:ffff::/64) and !(ip.dst == 0.0.0.0/8 or ip.dst == 10.0.0.0/8 or ip.dst == 100.64.0.0/10 or ip.dst == 127.0.0.0/8 or ip.dst == 127.0.53.53 or ip.dst == 169.254.0.0/16 or ip.dst == 172.16.0.0/12 or ip.dst == 192.0.0.0/24 or ip.dst == 192.0.2.0/24 or ip.dst == 192.168.0.0/16 or ip.dst == 198.18.0.0/15 or ip.dst == 198.51.100.0/24 or ip.dst == 203.0.113.0/24 or ip.dst == 224.0.0.0/4 or ip.dst == 240.0.0.0/4 or ip.dst == 255.255.255.255/32 or ipv6.dst == ::/128 or ipv6.dst == ::1/128 or ipv6.dst == ::ffff:0:0/96 or ipv6.dst == ::/96 or ipv6.dst == 100::/64 or ipv6.dst == 2001:10::/28 or ipv6.dst == 2001:db8::/32 or ipv6.dst == fc00::/7 or ipv6.dst == fe80::/10 or ipv6.dst == fec0::/10 or ipv6.dst == ff00::/8 or ipv6.dst == 2002::/24 or ipv6.dst == 2002:a00::/24 or ipv6.dst == 2002:7f00::/24 or ipv6.dst == 2002:a9fe::/32 or ipv6.dst == 2002:ac10::/28 or ipv6.dst == 2002:c000::/40 or ipv6.dst == 2002:c000:200::/40 or ipv6.dst == 2002:c0a8::/32 or ipv6.dst == 2002:c612::/31 or ipv6.dst == 2002:c633:6400::/40 or ipv6.dst == 2002:cb00:7100::/40 or ipv6.dst == 2002:e000::/20 or ipv6.dst == 2002:f000::/20 or ipv6.dst == 2002:ffff:ffff::/48 or ipv6.dst == 2001::/40 or ipv6.dst == 2001:0:a00::/40 or ipv6.dst == 2001:0:7f00::/40 or ipv6.dst == 2001:0:a9fe::/48 or ipv6.dst == 2001:0:ac10::/44 or ipv6.dst == 2001:0:c000::/56 or ipv6.dst == 2001:0:c000:200::/56 or ipv6.dst == 2001:0:c0a8::/48 or ipv6.dst == 2001:0:c612::/47 or ipv6.dst == 2001:0:c633:6400::/56 or ipv6.dst == 2001:0:cb00:7100::/56 or ipv6.dst == 2001:0:e000::/36 or ipv6.dst == 2001:0:f000::/36 or ipv6.dst == 2001:0:ffff:ffff::/64)","All Traffic that has no source or destination Bogons"

"Traffic//DCDiscovery","udp.port == 389 or dns.qry.type == 33","Displays frames associated with the Netlogon DSGETDC (DCDiscovery) process"

"Traffic//DNS+DoT","dns or tcp.port == 53 or udp.port == 53 or tcp.port == 853 or udp.port == 853","DNS and DNS over TLS traffic"

"Traffic//Errors","dns.flags.rcode > 0 or\x0ahttp.response.code > 399 or smb.nt_status > 0 or\x0asmb2.nt_status > 0","Show me DNS or HTTP or SMB errors"

"Traffic//Follow current Stream","tcp.stream == ${tcp.stream}","Follows the TCP stream of the selected TCP frame"

"Traffic//H/L TTL","ip.ttl <= 64 or ip.ttl > 128 or ipv6.hlim <= 64 or ipv6.hlim > 128","Check for TTL < 64 and > 128     Looking for intermediate networking devices"

"Traffic//ICMP//ICMP","icmp or icmpv6","ICMP"

"Traffic//ICMP//ICMP TTL Expired","icmp.type == 11 or icmpv6.type == 11","ICMP Time to live expired notification"

"Traffic//ICMP//OSFing","icmp.type == 13 or icmp.type == 15 or icmp.type == 17 or icmpv6.type == 13 or icmpv6.type == 15 or icmpv6.type == 17",""

"Traffic//ICMP//PING","icmp.type == 8 or  icmp.type == 0 or icmpv6.type == 8 or  icmpv6.type == 0","Show ICMP Echo Requests and Replies"

"Traffic//Latency//frame delta > 250ms","frame.time_delta_displayed >= .250",""

"Traffic//Latency//frame delta > 500ms","frame.time_delta_displayed >= .500","Any packets with greater than .5 second delta times"

"Traffic//Latency//frame delta > 750ms","frame.time_delta_displayed >= .750","Any packets with greater than .5 second delta times"

"Traffic//Latency//DNS > 400ms","dns.time > .4","Any DNS responses that are greater than .4 seconds"

"Traffic//Latency//HTTP > 400ms","http.time > .4","Any HTTP responses that are greater than .4 seconds"

"Traffic//Latency//SMB > 400ms","smb.time>.4 or smb2.time > .4","Any SMB responses that are greater than .4 seconds"

"Traffic//Malformed//SYN-noMSS","tcp.flags.syn == 1 and !tcp.options.mss_val","Any TCP SYN packets with no MSS"

"Traffic//Malformed//TCP SYN","((tcp.flags.reset == 1) and (tcp.seq == 1)) and (tcp.ack == 1)","Show me all packets with illegal TCP SYN flags"

"Traffic//Malformed//TCP and ICMP","tcp && icmp","Show me illegal packets that are ICMP in TCP"

"Traffic//RDP","(tcp.port == 3389) or (udp.port == 3389) ","Display only RDP traffic"

"Traffic//!RDP","!(tcp.port == 3389) or !(udp.port == 3389) ","Filter out all RDP traffic"

"Traffic//Net Scaler Reset Code","tcp.flags.reset == 1 and tcp.window_size_value >= 8146 and tcp.window_size_value <= 10042","Citrix Netscaler reset code in TCP window field (https://support.citrix.com/article/CTX200852)"

"Traffic//Redirects//HTTP","http.response.code > 299 and http.response.code < 400","Any HTTP Redirects"

"Traffic//Redirects//ICMP","icmp.type == 5 or icmpv6.type == 5","Any ICMP Redirects"

"Traffic//ReXmit","(tcp.analysis.retransmission or tcp.analysis.zero_window) and !(tcp.port == 3389 or udp.port == 3389)","TCP Retransmission"

"Traffic//TCP//TCP Flags","tcp.flags == 0x2 or\x0atcp.flags == 0xc2 or\x0atcp.flags == 0x12 or\x0atcp.flags == 0x52 or\x0atcp.flags == 0x14 or\x0atcp.flags == 0x4","DIsplay all frames where a TCP Flag is set"

"Traffic//TCP//TCP Analysis Flags","tcp.analysis.flags","Quick check on TCP Analysis Flags"

"Traffic//TCP//SYN","tcp.flags.syn == 1","Show me all the TCP SYNs"

"Traffic//TCP//Inititial Round Trip Time > 400ms","tcp.analysis.initial_rtt > .4","Any initial TCP RTT that are greater than .4 seconds"

"Traffic//TCP//TCP Latency > 400ms","tcp.time_delta > .4","Any TCP responses that are greater than .4 seconds"

"Traffic//WinRM","tcp.port == 5985 or tcp.port == 5986","Windown Remove Management (WinRM)"


# Packet list column format
# Each pair of strings consists of a column title and its format
gui.column.format: 

	"#", "%m",
	
	"PID", "%Cus:frame.comment:0:R",
	
	"?????", "%Tt",
	
	"ByIF", "%Cus:tcp.analysis.bytes_in_flight:0:R",
	
	"RTT", "%Cus:tcp.analysis.ack_rtt:0:R",
	
	"???", "%t",
	
	"Interface", "%Cus:frame.interface_description:0:R",
	
	"Source IP", "%s",
	
	"Destination IP", "%d",
	
	"SPort", "%Cus:tcp.srcport or udp.srcport:0:R",
	
	"DPort", "%Cus:tcp.dstport or udp.dstport:0:R",
	
	"Stream", "%Cus:tcp.stream:0:R",
	
	"Auth", "%Cus:kerberos or ntlmssp or radius or ldap.authentication or imap.request.username or mapi.EcDoConnect.name:0:R",
	
	"Username", "%Cus:radius.User_Name or ntlmssp.auth.username or imap.request.username or mapi.EcDoConnect.name or kerberos.CNameString or ntlmssp.auth.domain or ntlmssp.auth.hostname:0:R",
	
	"Kerberos Principle", "%Cus:kerberos.SNameString or kerberos.CNameString:0:R",
	
	"# Cert(s) + Size", "%Cus:tls.handshake.certificate_length:0:R",
	
	"CRL", "%Cus:x509ce.uniformResourceIdentifier:0:R",
	
	"LDAP assertion / SNI / URI / HTTP / Cert", "%Cus:tls.handshake.extensions_server_name or http.request or http.request.uri or http.request.line or dns.qry.name or ldap.assertionValue or x509sat.printableString:0:R",
	
	"Length", "%L",
	
	"TLS Protocols", "%Cus:tls.handshake.extensions.supported_version or tls.record.version or tls.handshake.version:0:R",
	
	"Protocol", "%p",
	
	"HTTP version", "%Cus:tls.handshake.extensions_alpn_str:0:R",
	
	"TTL", "%Cus:ip.ttl or ipv6.hlim:0:R",
	
	"Window", "%Cus:tcp.window_size_value:0:R",
	
	"Info", "%i"
