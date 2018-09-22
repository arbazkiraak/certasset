import sys,time
from socket import socket
import ssl,masscan
import M2Crypto
import OpenSSL,xml,threading
import Queue as queue

q = queue.Queue()
final_res = []

try:
    ip_range = sys.argv[1]
except:
    print('Usage: python subs_cert.py <IPRANGE>')
subs_ssl = []

try:
    mas = masscan.PortScanner()
    mas.scan(ip_range,ports='443')
    for host in mas.all_hosts:
        subs_ssl.append(host)
except (xml.etree.ElementTree.ParseError,masscan.masscan.NetworkConnectionError) as e:
    print('Probably iprange\'s is not valid/down')
    pass

def process_cert_subs(i):
    try:
        cert = ssl.get_server_certificate((str(i), 443))
        x509 = M2Crypto.X509.load_cert_string(cert)
        cert_val = x509.get_subject().as_text()
        cnames = cert_val.split('CN=')[1]
        if len(cnames) > 0:
            print(cnames)
    except SSLEOFError as e:
        pass

def process_queue():
    while not q.empty():
        current_ip = q.get()
        process_cert_subs(current_ip)
        q.task_done()

if len(subs_ssl) > 0:
    for i in subs_ssl:
        i = str(i)
        i = i.strip('\n')
        i = i.strip('\r')
        q.put(i)
else:
    print('Empty ips.. Exiting..')
    sys.exit(1)

for i in range(100):
    t = threading.Thread(target=process_queue)
    t.start()
