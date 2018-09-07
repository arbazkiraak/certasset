import sys,time
from socket import socket
import ssl,masscan
import M2Crypto
import OpenSSL

ip_range = sys.argv[1]
subs_ssl = []

mas = masscan.PortScanner()
mas.scan(ip_range,ports='443')
for host in mas.all_hosts:
    subs_ssl.append(host)

for i in subs_ssl:
    cert = ssl.get_server_certificate((str(i), 443))
    x509 = M2Crypto.X509.load_cert_string(cert)
    cert_val = x509.get_subject().as_text()
    cnames = cert_val.split('CN=')[1]
    print(cnames)
