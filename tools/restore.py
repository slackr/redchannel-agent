import os
import sys
import shutil

def encrypt_string(data, key):
    encrypted_string = []
    
    # encrypt everything but surrounding quotes
    for i in range(len(data)):
        encrypted_string.append('0x{:02x}'.format(ord(data[i]) ^ key))

    return ", ".join(encrypted_string)

if len(sys.argv) < 2:
    print("[!] usage: python3 " + sys.argv[0] + " /path/to/agent/")
    sys.exit(1)

search_dir = sys.argv[1]

print("[+] restoring *.go files in: " + search_dir)

for d, dirs, files in os.walk(search_dir):
    for f in files:
        if not f.endswith('.org'):
            continue

        original = os.path.join(d, f)
        overwrite = original[:-4]
        print("[+] moving '" + original + "' to '" + overwrite + "'")
        shutil.move(original, overwrite)

print("[+] restore done!")