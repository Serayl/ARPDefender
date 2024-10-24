import ARPDefenderBase
from scapy.all import *
from scapy.layers.l2 import Ether
import json
import signal
from OSFunctions import arp_lookup, show_notification_arp_mitm
from Crypto import load_private_key, sign_json, encrypt


class ARPDefenderActive(ARPDefenderBase.ARPDefenderBase):
    __current_sequence = 0
    __sequence_file = ""
    __defender_protocol = "0xbb80"

    def __init__(self, password):
        super().__init__()
        self.__sequence_file = os.path.join("data", "sequence.txt")
        if not os.path.exists(self.__sequence_file):
            with open(self.__sequence_file, "w") as f:
                f.write("0")
        self.__current_sequence = self.load_sequence()
        # Ideally we would at least secure this with a system credential based keyring
        self.__password = password

    def load_sequence(self):
        with open(self.__sequence_file, 'r') as f:
            return int(f.read())

    # Creates a notification for an ARP poisoning mitm attack, signs it and encrypts it
    def notify(self, attack_type="mitm", attacker="", target1="", target2="", target1_ip="", target2_ip=""):
        with open(os.path.join("data", 'symmetric.bin'), 'rb') as symmetric_file:
            key = symmetric_file.read(32)
        # create notification
        notification = {
            "type": attack_type,
            "attacker": attacker,
            "target1": target1,
            "target1ip": target1_ip,
            "target2": target2,
            "target2ip": target2_ip,
            "sequence": str(self.__current_sequence + 1),
        }
        # serialize, sign, encode and return the notification
        notification_json = json.dumps(notification)
        private_key_path = os.path.join("data", 'private_key.pem')
        private_key = load_private_key(private_key_path, self.__password)
        signature = sign_json(private_key, notification_json)
        notification_data = notification_json + "*" + signature.hex()
        iv, encrypted_data = encrypt(notification_data.encode("utf-8"), key)
        self.__current_sequence = self.__current_sequence + 1
        with open(self.__sequence_file, "w") as f:
            f.write(str(self.__current_sequence))
        return iv, encrypted_data

    #
    def detect2(self, packet, active=True):
        my_mac = get_if_hwaddr(conf.iface)
        origin_mac = packet[Ether].src
        destination_mac = packet[Ether].dst
        payload = packet[Ether].payload
        pckt = packet
        protocol_number = int(self.__defender_protocol, 16)
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
                    target1_ip = arp_lookup(target1_mac)
                    target2_ip = arp_lookup(target2_mac)
                    if active:
                        # send notification through the defender protocol
                        notification_iv, notification_ciphertext = self.notify("mitm", attacker_mac, target1_mac, target2_mac, target1_ip, target2_ip)
                        notification_packet = Ether(dst=target1_mac, src=my_mac, type=protocol_number) / (
                                notification_iv + notification_ciphertext)
                        sendp(notification_packet)
                        notification_iv, notification_ciphertext = self.notify("mitm", attacker_mac, target1_mac, target2_mac, target1_ip, target2_ip)
                        notification_packet = Ether(dst=target2_mac, src=my_mac, type=protocol_number) / (
                                notification_iv + notification_ciphertext)
                        sendp(notification_packet)
                    try:
                        show_notification_arp_mitm(attacker_mac, target1_mac,
                                                   target1_ip,
                                                   target2_mac,
                                                   target2_ip)
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

    # Starts passive detection of ARP mitm attacks
    def active_detection(self):
        sniff(prn=self.detect2)
