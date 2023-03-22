import pyshark

cap = pyshark.FileCapture('Packets/Edurom/Cree+Ferme-meet-instantané-no-micro-no-camera- 20 ⁄ 03.pcapng')

DNS_Resolved = []
DNS_RequestsType = {1: 0, 28: 0}
QUIC_Versions = {}
tempDNS = []
print(str(cap[27].quic.version) in QUIC_Versions)
i = 1

for packet in cap:
    if 'DNS' in packet:
        if str(packet.dns.flags) == "0x8180":
            DNS_Resolved.append(packet.frame_info.time_relative)  # (y a aussi time_epoch et time)
            # Notez entreprise
            if packet.dns.flags_authoritative != 0:
                print(i)
                # Pas encore de paquets avec 1 (avec les 2 paquets)
            if int(packet.dns.qry_type) == 1:
                DNS_RequestsType.update({1: DNS_RequestsType.get(1) + 1})
            else:
                DNS_RequestsType.update({28: DNS_RequestsType.get(28) + 1})
            # Record additionnel??
            # Comportements DNS inattendus??
    # if 'QUIC' in packet:
    #     if packet.quic str(packet.quic.version) in QUIC_Versions:
    #         QUIC_Versions.update({str(packet.quic.version): QUIC_Versions.get(str(packet.quic.version)) + 1})
    #     else:
    #         QUIC_Versions.update({str(packet.quic.version): 1})
    # i += 1


print("Resolved: ", len(DNS_Resolved))
print(DNS_RequestsType)
