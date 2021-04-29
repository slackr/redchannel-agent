import os
import sys
import re
import random
import codecs

template = """(func() string {
    s := []byte{[BYTES]}
    k := [KEY]
    for i, c := range s {
        s[i] = byte(int(c) ^ k)
    }
    return string(s)
}())"""

def encrypt_string(data, key):
    encrypted_string = []
    
    # encrypt everything but surrounding quotes
    for i in range(len(data)):
        encrypted_string.append('0x{:02x}'.format(ord(data[i]) ^ key))

    return ", ".join(encrypted_string)

def obfs_strings(data):
    strings = re.findall(r'[\s\(](\".{2,}\")[\),]', data, flags=re.IGNORECASE)
    config_strings = re.findall(r'\s*c\..+[a-z=]\s*(\".{2,}\")', data, flags=re.IGNORECASE)

    strings.extend(config_strings)

    for s in strings:
        decrypt_string = template
        key = random.randint(0x7F, 0xFF)

        decrypt_string = decrypt_string.replace("[KEY]", '0x{:02x}'.format(key))

        # [1:-1] strips quotes
        enc_bytes = encrypt_string(s[1:-1], key)
        decrypt_string = decrypt_string.replace("[BYTES]", enc_bytes)
        print("encrypted: '" + s + "' with key '" + '0x{:02x}'.format(key) + "' = {" + enc_bytes + "}")

        data = data.replace(s, decrypt_string)
    return data



if len(sys.argv) < 2:
    print("[!] usage: python3 " + sys.argv[0] + " /path/to/agent/")
    sys.exit(1)

search_dir = sys.argv[1]

print("[+] obfuscating Go strings in: " + search_dir)

for d, dirs, files in os.walk(search_dir):
    for f in files:
        if not f.endswith('.go'):
            continue

        path = os.path.join(d, f)
        with codecs.open(path, 'r', encoding='utf8') as f:
            contents = f.read()

        # backups to be restored after compile
        with codecs.open(path + '.org', 'w', encoding='utf8') as f:
            f.write(contents)

        # replace debug statements with random int prints since golang complains if you import a library and dont use it
        contents = re.sub(r'(.*fmt|log)\.Printf\(.+', r'\1.Print(1)', contents, flags=re.IGNORECASE)
        contents = obfs_strings(contents)

        with codecs.open(path, 'w', encoding='utf8') as f:
            f.write(contents)

print("[+] obfuscation done! 'go build' and restore from *.org files")