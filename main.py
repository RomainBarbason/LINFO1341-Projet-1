import pyshark
import os

DNS_Resolved = []
DNS_ResolvedTime = []
DNS_RequestsType = {1: 0, 28: 0}
QUIC_Versions = {}
tempDNS = []

dirc = "Packets/Edurom"

for filename in os.listdir(dirc):
    file = os.path.join(dirc, filename)
    # checking if it is a file
    if os.path.isfile(file):
        print(file)
        cap = pyshark.FileCapture(file)
        i = 1
        for packet in cap:
            if 'DNS' in packet:
                if str(packet.dns.flags) == "0x8180":
                    DNS_ResolvedTime.append(packet.frame_info.time_relative) # (y a aussi time_epoch et time)
                    if str(packet.dns.qry_name) not in DNS_Resolved:
                        DNS_Resolved.append(str(packet.dns.qry_name))
                    if int(packet.dns.flags_authoritative) == 1:
                        print(i)
                    if int(packet.dns.qry_type) == 1:
                        DNS_RequestsType.update({1: DNS_RequestsType.get(1) + 1})
                    else:
                        DNS_RequestsType.update({28: DNS_RequestsType.get(28) + 1})
                    if int(packet.dns.flags_rcode) != 0:
                        print(i)
                if int(packet.dns.count_add_rr) != 0:
                    print(i)
            if 'QUIC' in packet:
                if int(packet.quic.header_form) == 1:
                    if str(packet.quic.version) in QUIC_Versions:
                        QUIC_Versions.update({str(packet.quic.version): QUIC_Versions.get(str(packet.quic.version)) + 1})
                    else:
                        QUIC_Versions.update({str(packet.quic.version): 1})
            i += 1



print("Resolved: ", len(DNS_ResolvedTime))
print(DNS_Resolved)
print(DNS_RequestsType)
print(QUIC_Versions)

"""
Questions pour réseaux(jme refere au rapport):
2A: Combien de noms de domaines au total? en moyenne ?
2C: On check ca comment?
"""
