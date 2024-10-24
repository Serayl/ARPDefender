import os
import signal
import sys

from Crypto import generate_keys
from ARPDefenderActive import ARPDefenderActive
from ARPDefenderBase import ARPDefenderBase
from ARPPoison import ARPPoison
from ARPDefenderActiveListener import ARPDefenderActiveListener


class ARPDefender:

    def __init__(self):
        pass

    @staticmethod
    def __show_help():
        print(
            "Usage: ARPDefender.py [start [active/passive/listener/mitm]/install/help] [-t1 target1 -t2 target2] [active/passive] [-p <password>]")
        print(
            "Installation requires an active/passive argument for the type of installation. Active installation will generate asymmetric keys for its use. The public key in this pair and the symmetric key will need to be ported to all active listeners.")
        print("Active defense and installation require a password to secure the generated private key or access it.")
        print("mitm attack requires target1 and target2 IP addresses in 192.168.1.1 format")

    @staticmethod
    def __signal_handler(sig, frame):
        sys.exit(0)

    @staticmethod
    def __not_installed():
        return not os.path.exists("data") or not os.path.exists(os.path.join("data", "logs"))

    @staticmethod
    def __no_keys():
        return not os.path.exists(os.path.join("data", 'symmetric.bin')) or not os.path.exists(
            os.path.join("data", 'public_key.pem'))

    @staticmethod
    def __no_private_keys():
        return ARPDefender.__no_keys() or not os.path.exists(os.path.join("data", 'salt.bin')) or not os.path.exists(
            os.path.join("data", 'private_key.pem'))

    def start(self):
        args = sys.argv[1:]
        signal.signal(signal.SIGINT, self.__signal_handler)
        if len(args) < 1 or args[0] == "help":
            ARPDefender.__show_help()
            sys.exit(0)
        elif args[0] != "install" and self.__not_installed():
            print(
                "Please install ARPDefender using ARPDefender.py install [active/passive] [-p <password>] before using it")
            sys.exit(0)
        elif args[0] == "install":
            if len(args) < 2 or (args[1] == "active" and (len(args) < 4 or args[2] != "-p")):
                ARPDefender.__show_help()
                sys.exit(0)
            if not os.path.exists("data"):
                os.makedirs("data")
            if not os.path.exists(os.path.join("data", "logs")):
                os.makedirs(os.path.join("data", "logs"))
            with open(os.path.join("data", "excluded_mac.txt"), "w") as f:
                pass
            if args[1] == "active":
                generate_keys(args[3])
            print("Installation successful.")
            sys.exit(0)
        elif args[0] == "start" and args[1] == "active":
            if len(args) < 4 or args[2] != "-p":
                ARPDefender.__show_help()
                sys.exit(0)
            if self.__no_private_keys():
                print("No keys found, please install. Exiting.")
                sys.exit(0)
            defender = ARPDefenderActive(args[3])
            defender.active_detection()
        elif args[0] == "start" and args[1] == "passive":
            defender = ARPDefenderBase()
            defender.passive_detection()
        elif args[0] == "start" and args[1] == "mitm":
            if len(args) < 6 or args[2] != "-t1" or args[4] != "-t2":
                ARPDefender.__show_help()
                sys.exit(0)
            defender = ARPPoison(args[3], args[5])
            defender.arp_poison_mitm()
        elif args[0] == "start" and args[1] == "listener":
            if self.__no_keys():
                print(
                    "No public and symmetric keys found please port data/public_key.pem and data/symmetric.bin from your active installation folder. Exiting.")
                sys.exit(0)
            defender = ARPDefenderActiveListener()
            try:
                defender.defender_listener()
            except KeyboardInterrupt:
                sys.exit(0)
        else:
            ARPDefender.__show_help()
            sys.exit(0)


if __name__ == "__main__":
    ARPdefender = ARPDefender()
    ARPdefender.start()
