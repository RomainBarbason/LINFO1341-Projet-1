import pyshark

cap = pyshark.FileCapture('Packets/Edurom/Cree+Ferme-meet-instantané-no-micro-no-camera- 20 ⁄ 03.pcapng')

DNS_Resolved = 0
DNS_RequestsType = {}
tempDNS = []

for packet in cap:
    if 'DNS' in packet:
        if packet.flags == 0x8180:
            DNS_Resolved += 1
            #Notez entreprise
            if packet.dns.flags_authoritative != 0:
                pass
                #Pas encore de paquets avec 1 (avec les 2 paquets)
            if packet.dns.qry_type not in tempDNS:
                tempDNS.append(packet.dns.qry_type)
            #Record additionnel??
            #Comportements DNS inattendus??

    #TODO Serveurs autoritatifs

