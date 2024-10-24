from scapy.all import *
from scapy.layers.l2 import ARP, Ether
from OSFunctions import is_valid_mac_address, arp_lookup, show_notification_arp_mitm
import signal


class ARPDefenderBase:
    #count = 0
    def __init__(self):
        scapy.verbose = 0
        conf.use_pcap = True
        conf.sniff_promisc = True
        self._pck_list = []
        self._excluded_mac = []
        self._tracked_list = []
        self._max_length = 5000
        self.import_exclusion_list(os.path.join("data", "excluded_mac.txt"))
        self._log_dir = os.path.join("data", "logs")
        if not os.path.exists(self._log_dir):
            os.makedirs(self._log_dir)

    # Compare two payloads in lazy fashion, returning false as soon as a byte does not match
    @staticmethod
    def lazy_compare(payload1, payload2):
        p1 = raw(payload1)
        p2 = raw(payload2)
        if len(p1) != len(p2):
            return False
        for i in range(len(p1)):
            if p1[i] != p2[i]:
                return False
        return True

    def exclude_mac(self, mac_address):
        if mac_address not in self._excluded_mac and is_valid_mac_address(mac_address):
            self._excluded_mac.append(mac_address)

    def import_exclusion_list(self, exclusion_file):
        with open(exclusion_file, 'r') as f:
            for line in f:
                self.exclude_mac(line.strip())

    # Detects mitm attacks with one middle interface, launches an alert when detecting one and logs all associated packets
    def detect(self, packet):
        origin_mac = packet[Ether].src
        destination_mac = packet[Ether].dst
        payload = packet[Ether].payload
        pckt = packet
        self._pck_list.append((origin_mac, destination_mac, payload, pckt))
        for old_packet in self._pck_list:
            old_origin, old_destination, old_payload, _ = old_packet
            if (old_destination not in self._excluded_mac and old_destination == origin_mac) and self.lazy_compare(
                    old_payload,
                    payload):  # old_payload==payload:
                attacker_mac = old_destination
                target1_mac = old_origin
                target2_mac = destination_mac
                if ((attacker_mac, target1_mac, target2_mac) not in self._tracked_list
                        and (attacker_mac, target2_mac, target1_mac) not in self._tracked_list):
                    self._tracked_list.append((attacker_mac, target1_mac, target2_mac))
                    try:
                        show_notification_arp_mitm(attacker_mac, target1_mac,
                                                   arp_lookup(target1_mac), target2_mac,
                                                   arp_lookup(target2_mac))
                        # A custom notification action such as mailing can be added here
                    except NotImplementedError as e:
                        print(
                            "Alert ARP poisoning MITM attack:\n Attacker:\t" + attacker_mac + "\nVictim1:\t" + target1_mac + "\nVictim2:\t" + target2_mac + "\n\t")
                        continue
                # Logging could optionally be only done in the passive listener
                replaced_mac = attacker_mac.replace(':', '-')
                filename = os.path.join(self._log_dir, f"{replaced_mac}.log")
                with open(filename, 'a') as f:
                    f.write(f"{datetime.now()} - {packet.summary()}\n")
                self._pck_list.remove(old_packet)
        if len(self._pck_list) >= self._max_length:
            self._pck_list.pop(0)
        #self.count = self.count + 1
        #print(self.count)

    # Starts passive detection of ARP mitm attacks
    def passive_detection(self):
        #self.count = 0
        sniff(prn=self.detect)
