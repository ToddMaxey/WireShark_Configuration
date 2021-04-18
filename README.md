# WireShark_Configuration
This is my person Wireshark configuration. This aids me in troubleshooting by adding new columns and filter buttons to help identify networking and or machine configuration issues. 

Additions - Columns

⌚Δ (time delta) Type Delta time

ByIF (Bytes In Flight) tcp.analysis.bytes_in_flight

SPort (Source Port) tcp.srcport or udp.srcport

DPort (Destination Port) tcp.dstport or udp.dstport

Auth (Authenication) kerberos or ntlmssp or radius or ldap.authentication or imap.request.username or mapi.EcDoConnect.name

Cert (Certificate) tls.handshake.certificates or pkcs12 or x509af or x509ce or x509if or x509sat

Auth Username (Authenication Username) ldap.assertionValue or radius.User_Name or ntlmssp.auth.username or imap.request.username or mapi.EcDoConnect.name or kerberos.CNameString

TLS URL Endpoint (TLS URL Endpoint) tls.handshake.extensions_server_name

TTL (Time To Live) ip.ttl or ipv6.hlim


Additions - Filter Buttons

HTTPS - tcp.port == 443

TLS Handshake - tls.handshake.type >= 1

Proxy Connects - http.request.method == "CONNECT"

DC Discovery - udp.port == 389 or dns.qry.type == 33

Auth - kerberos or ntlmssp or radius or ldap.authentication or udp.port == 1812 or udp.port == 1813 or udp.port == 1645 or udp.port == 1646 or tcp.port ==88  or udp.port == 88 or imap.request.username or mapi.EcDoConnect.name or kerberos.CNameString or tls.handshake.extensions_server_name == "autologon.microsoftazuread-sso.com" or tls.handshake.extensions_server_name == "adnotifications.windowsazure.com" or tls.handshake.extensions_server_name == "logon.microsoftonline.com"

High/Low TTL - ip.ttl < 64 or ip.ttl > 128 or ipv6.hlim < 64 or ipv6.hlim > 128

ReXmit - tcp.analysis.retransmission

DNS - dns or tcp.port == 53 or udp.port == 53

ICMP - icmp or icmpv6

Remove RDP - !(tcp.port == 3389) and !(udp.port == 3389)

TCP Flags - tcp.flags == 0x2 or tcp.flags == 0xc2 or tcp.flags == 0x12 or tcp.flags == 0x52 or tcp.flags == 0x14 or tcp.flags == 0x4

TLS Alerts - (tls.record.content_type == 21) && (tls.record.length < 26)
