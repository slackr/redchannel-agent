import sys
import os
import subprocess

def run_command(command, environment):
    env = os.environ.copy()

    if environment is not None:
        env = env.update(environment)

    p = subprocess.Popen(command, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, universal_newlines=True)
    print("running: " + ' '.join(command))
    output = ""
    for line in p.stdout.readlines():
        output = output + line
    retval = p.wait()
    print(output)
    
    return retval

def obfuscate_agent(build_path):
    obfs_command = [
        'python',
        '{0}/tools/obfuscate.py'.format(build_path),
        build_path
    ]

    return run_command(obfs_command, None)

def build_agent(build_path, output_file, goos, goarch):
    if build_path[len(build_path)-1] == "\\" or build_path[len(build_path)-1] == "/": 
        build_path = build_path[:-1]

    env = {
        'GOOS': goos,
        'GOARCH': goarch,
        'GOCACHE': build_path + "/gocache/",
        'GOPATH': build_path,
    }

    # dependencies
    build_command = [
        'go', 'get', 'github.com/miekg/dns'
    ]

    ret = run_command(build_command, env)
    if ret != 0:
        print("[!] failed to 'go get' dependencies: {0}".format(ret))
        return ret

    build_command = [
        'go',
        'build',
        '-a',
        '-v',
        '-x',
        '-o',
        '-ldflags=-w',
        '-ldflags=-s',
        '-gcflags=all=-trimpath={0}'.format(build_path),
        '-asmflags=all=-trimpath={0}'.format(build_path),
        '-o',
        '{0}'.format(output_file)
    ]
    
    return run_command(build_command, env)
    
def restore_code(build_path):
    restore_command = [
        'python',
        '{0}/tools/restore.py'.format(build_path),
        build_path
    ]
    ret = run_command(restore_command, None)
    if ret != 0:
        print("[!] failed to restore code: {0}".format(ret))

    return ret

if len(sys.argv) < 5:
    print("[!] usage: python3 " + sys.argv[0] + " </path/to/agent/> </path/to/agent/build/agent.exe> <GOOS> <GOARCH> [debug]")
    sys.exit(1)

build_path = sys.argv[1]
output_file = sys.argv[2]
goos = sys.argv[3]
goarch = sys.argv[4]

debug = False
if len(sys.argv) == 6 and sys.argv[5] == 'debug':
    print("[+] DEBUG: this is a debug build, agent will be verbose")
    debug = True

if debug == False:
    print("[+] obfuscating agent source in: " + build_path)
    ret = obfuscate_agent(build_path)
    if ret != 0:
        print("[!] failed to obfuscate agent: {0}".format(ret))
        restore_code(build_path)
        sys.exit(1)

print("[+] building agent in: " + build_path)
ret = build_agent(build_path, output_file, goos, goarch)
if ret != 0:
    print("[!] failed to build agent: {0}".format(ret))
    restore_code(build_path)
    sys.exit(1)

if debug == False:
    restore_code(build_path)

print("[+] done!")