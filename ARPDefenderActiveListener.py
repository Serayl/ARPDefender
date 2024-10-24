from Crypto import decrypt, verify_signature_json, load_public_key
import os
import json
from scapy.all import *
from scapy.layers.l2 import Ether as Ether
from OSFunctions import arp_lookup, add_static_arp_entry, show_notification_arp_mitm, is_valid_mac_address


class VerificationException(Exception):
    pass


class ARPDefenderActiveListener:
    __current_sequence = 0
    __sequence_file = ""
    __defender_protocol = "0xbb80"

    def __init__(self):
        self.__sequence_file = os.path.join("data", "sequence.txt")
        if not os.path.exists(self.__sequence_file):
            with open(self.__sequence_file, "w") as f:
                f.write("0")
        self.__current_sequence = self.load_sequence()
        # Ideally we would at least secure this with a system credential based keyring

    def load_sequence(self):
        with open(self.__sequence_file, 'r') as f:
            sequence = int(f.read())
        return sequence

    # Verifies a defender protocol message created by the function notify under ARPDefenderActive.py
    def verify(self, message):
        with open(os.path.join("data", 'symmetric.bin'), 'rb') as symmetric_file:
            key = symmetric_file.read(32)
        public_key = load_public_key(os.path.join("data", 'public_key.pem'))
        # The RSA signature has to be smaller than the modulus which is 2048 bits, so 256 bytes,
        # to which we add the serialized JSON size, possibly multiplied up to a factor 4/3 by the encoding
        # into base64 or ascii. Giving some margin, we will accept sizes 784 and lower
        # (AES will have padded to a multiple of 128 bytes, and we added 16 bytes for the IV).
        if len(message) > 784:
            raise VerificationException("Message too long")
        if len(message) % 16 != 0:
            raise VerificationException("Invalid message")
        # decrypt message
        try:
            decrypted = decrypt(message, key)
            decrypted_message = decrypted.decode("utf-8")
            split = decrypted_message.split("*")
            json_dicts = split[0]
            json_dict = json.loads(json_dicts)
            signature = bytes.fromhex(split[1])
            verified = verify_signature_json(public_key, signature, json_dicts)
            if not verified:
                raise VerificationException("Invalid signature")
            received_sequence = int(json_dict["sequence"])
            self.__current_sequence = self.load_sequence()
            if received_sequence <= self.__current_sequence:
                raise VerificationException("Invalid nonce")
            else:
                current_sequence = received_sequence
                with open(os.path.join("data", 'sequence.txt'), 'w') as sequence_file:
                    sequence_file.write(str(current_sequence))
            return verified, json_dict["attacker"], json_dict["target1"], json_dict["target2"], json_dict["target1ip"], json_dict["target2ip"]
        except Exception as e:
            raise VerificationException()

    @staticmethod
    def __repair(target_mac, json_ip):
        try:
            target_ip = arp_lookup(target_mac)
            if target_ip == "":
                target_ip = json_ip
            add_static_arp_entry(target_ip, target_mac)
            return target_ip
        except NotImplementedError as e:
            print(e)
            return None

    # Acts on each received defender protocol message to verify it and statically modify the ARP cache to stop an attack.
    def active_defense(self, packet, local_notification=True):
        my_mac = get_if_hwaddr(conf.iface)
        my_ip = get_if_addr(conf.iface)
        protocol_number = int(self.__defender_protocol, 16)
        if Ether in packet and packet[Ether].type == protocol_number:
            if Raw in packet:
                payload = packet[Raw].load
                try:
                    verified, attacker, target1, target2, target1_ip_json, target2_ip_json = self.verify(payload)
                except VerificationException as e:
                    print(e)
                    return None
                if verified and is_valid_mac_address(target1) and is_valid_mac_address(target2):
                    if target1 == my_mac:
                        target2_ip = self.__repair(target2, target2_ip_json)
                        if target2_ip is not None and local_notification:
                            show_notification_arp_mitm(attacker, my_mac, my_ip, target2, target2_ip)
                        return target2, target2_ip
                        """
                        try:
                            target2_ip = arp_lookup(target2)
                            if target2_ip == "":
                                target2_ip = target2_ip_json
                            add_static_arp_entry(target2_ip, target2)
                            if local_notification:
                                show_notification_arp_mitm(attacker, my_mac, my_ip, target2, target2_ip)
                            return target2, target2_ip
                        except NotImplementedError as e:
                            print(e)
                            return None
                        """
                    elif target2 == my_mac:
                        target1_ip = self.__repair(target1, target1_ip_json)
                        if target1_ip is not None and local_notification:
                            show_notification_arp_mitm(attacker, my_mac, my_ip, target1, target1_ip)
                        return target1, target1_ip
                        """
                        try:
                            target1_ip = arp_lookup(target1)
                            if target1_ip == "":
                                target1_ip = target1_ip_json
                            add_static_arp_entry(target1_ip, target1)
                            if local_notification:
                                show_notification_arp_mitm(attacker, my_mac, my_ip, target1, target1_ip)
                            return target1, target1_ip
                        except NotImplementedError as e:
                            print(e)
                            return None
                        """
            """
                    else:
                        return None
                else:
                    return None
            else:
                return None
            """
        return None

    # Launches the listener using scapy.
    def defender_listener(self):
        try:
            my_mac = get_if_hwaddr(conf.iface)
            #TODO test with new filter
            sniff(prn=self.active_defense, filter='ether dst ' + my_mac + ' and ether proto ' + self.__defender_protocol)
        except KeyboardInterrupt:
            print("Interrupted")
            raise KeyboardInterrupt
