import pyshark
import os
import matplotlib.pyplot as plt

DNS_Resolved = []
DNS_ResolvedTime = []
DNS_RequestsType = {1: 0, 28: 0}
QUIC_Versions = {}
tempDNS = []
countA = 0
countAAAA = 0
TransportProtocolType = {"UDP": 0, "TCP": 0}
tempTransport = []

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
                if packet.dns.qry_type == '1':
                    countA += 1
                elif packet.dns.qry_type == '28':
                    countAAAA += 1
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
            if 'UDP' in packet:
                TransportProtocolType.update({'UDP': TransportProtocolType.get('UDP') + 1})
            if 'TCP' in packet:
                print(packet)
                TransportProtocolType.update({'TCP': TransportProtocolType.get('TCP') + 1})
            i += 1

googleDomains = 0
otherDomains = 0
for elem in DNS_Resolved:
    if "google" in str(elem):
        googleDomains += 1
    else:
        otherDomains += 1
        print(elem)


labels = 'Google', 'Autres'
sizes = [googleDomains,otherDomains]

fig, ax = plt.subplots()
ax.pie(sizes, labels=labels, autopct='%1.1f%%')
#plt.savefig('graph1.png', bbox_inches='tight')
#plt.show()

print("Resolved: ", len(DNS_Resolved))
print("A:",countA)
print("AAAA: ",countAAAA)
print("Resolved: ", len(DNS_ResolvedTime))
print(DNS_Resolved)
print(DNS_RequestsType)
print(QUIC_Versions)
print(TransportProtocolType)

"""
Questions pour réseaux(jme refere au rapport):
2A: Combien de noms de domaines au total? en moyenne ?
2C: On check ca comment?
"""
