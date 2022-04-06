#!/usr/bin/python3
import argparse
from datetime import datetime
from time import sleep
from bcc import BPF, USDT
import json
import os
from parsexml import parse_xml
from packaging.version import parse
from packaging.specifiers import SpecifierSet

# period
PERIOD = 10

def filter_relevant_vulnerabilities(db, dependencies):
    operators = {
        "gt": ">",
        "gte": ">=",
        "lt": "<",
        "lte": "<="
    }

    indices_to_be_deleted = []
    for dep in dependencies:
        if dep['version']:
            package_name = dep['groupId'] + ":" + dep['artifactId']
            package_version = parse(dep['version'])
            for index, vuln in enumerate(db):
                if package_name == vuln['package_name']:
                    version_range = list(filter(lambda e: e[1] != '~', list(vuln['version_range'].items())))
                    specifier_set = ",".join(list(map(lambda e: operators[e[0]] + e[1],version_range)))
                    if not package_version in SpecifierSet(specifier_set):
                        indices_to_be_deleted.append(index)
    for i in sorted(indices_to_be_deleted, reverse=True):
        del db[i]
    return db

# Text colors
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Get arguments from command line
parser = argparse.ArgumentParser(
    description="Trace Java applications.",
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("pid", type=int, help="process id to attach to")
parser.add_argument("-v", "--verbose", action="store_true",
    help="verbose mode: print the BPF program (for debugging purposes)")
parser.add_argument("--pom", "--only-versions-from-pom", type=str)

args = parser.parse_args()

# pom file parser
if not args.pom:
    print(f"{bcolors.WARNING}pom.xml not provided. Version filtering cannot be performed. This will increase the number of false positives.\n{bcolors.ENDC}")
else:
    pom_file = args.pom
    dep_list = parse_xml(pom_file)

# BPF program
program = """
#define MAX_STRING_LENGTH 160

struct method_t {
    char clazz[MAX_STRING_LENGTH];
    char method[MAX_STRING_LENGTH];
};

struct entry_t {
    u64 pid;
    struct method_t method;
};

BPF_HASH(counts, struct method_t, u64);

int trace_entry(struct pt_regs *ctx) {
    u64 clazz = 0, method = 0, val = 0;
    u64 *p;
    struct entry_t data = {0};
    data.pid = bpf_get_current_pid_tgid();
    bpf_usdt_readarg(2, ctx, &clazz);
    bpf_usdt_readarg(4, ctx, &method);
    bpf_probe_read(&data.method.clazz, sizeof(data.method.clazz),
                   (void *)clazz);
    bpf_probe_read(&data.method.method, sizeof(data.method.method),
                   (void *)method);

    p = counts.lookup(&data.method);
    if (p != 0) {
        val = *p;
    }
    val++;
    counts.update(&data.method, &val);

    return 0;
}
"""

# usdt
usdt = USDT(pid=args.pid)
entry_probe = "method__entry"
usdt.enable_probe_or_bail(entry_probe, "trace_entry")

if args.verbose:
    if args.verbose and usdt:
        print(usdt.get_text())
    print(program)

# Attach BPF program to USDT probes
bpf = BPF(text=program, usdt_contexts=[usdt] if usdt else [])

# Load vulnerability dataset
f = 'arvos_vfs_java.json'

with open(f) as json_file:
    data = json_file.read()

if not args.pom:
    vuln_obj = json.load(data)["VF_items"] 
else :
    vuln_obj = filter_relevant_vulnerabilities(json.loads(data)["VF_items"], dep_list)

# Stack trace file
stack_trace = "/stack_logs/stack-traces.log"

# If stack traces don't exist, continue without it

# Check if scanning has started
if not os.path.exists(stack_trace):
    print(f"{bcolors.WARNING}Stack traces don't exist ... continuing without stack traces ...{bcolors.ENDC}\n")
else:
    with open(stack_trace) as f:
        stack_output = f.read()
    # Load it into an array
    stack_array = stack_output.split(os.linesep + os.linesep)

# keep track of invoked vulnerable symbols
vuln_count = 0

print(f"{bcolors.OKGREEN}\nTracing Java calls in process %d and scanning for vulnerable symbols ... Ctrl-C to quit.{bcolors.ENDC}" % (args.pid))

# Loop until exit
while True:
    try:
        sleep(PERIOD)
        os.system('clear')

        invoked_class_list = []
        invoked_method_list = []
    
        for k,v in bpf["counts"].items():
            invoked_class_list.append(k.clazz.decode('utf-8', 'replace').replace('/', '.'))
            invoked_method_list.append(k.method.decode('utf-8', 'replace'))
        
        for i in range(len(invoked_class_list)):
            for item in vuln_obj:
                for sym in item['symbols']:
                
                    if sym['class_name'] in invoked_class_list[i] and sym['method_name'] in invoked_method_list[i]:

                        vuln_count += 1
                    
                        t_now = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")

                        print(f"\n{bcolors.FAIL}Vulnerable symbol invoked!!!")
                        print(f"\t{bcolors.FAIL}Time:{bcolors.ENDC} {t_now}")
                        print(f"\t{bcolors.FAIL}Vulnerability:{bcolors.ENDC} {item['vulnerability']}")
                        print(f"\t{bcolors.FAIL}Repository:{bcolors.ENDC} {item['repository']}")
                        print(f"\t{bcolors.FAIL}Invoked Class:{bcolors.ENDC} {sym['class_name']}")
                        print(f"\t{bcolors.FAIL}Invoked Method:{bcolors.ENDC} {sym['method_name']}")
                        print(f"\t{bcolors.FAIL}Confidence:{bcolors.ENDC} {item['confidence']}")
                        print(f"\t{bcolors.FAIL}Spread:{bcolors.ENDC} {item['spread']}")
                        print(f"\t{bcolors.FAIL}Package name:{bcolors.ENDC} {item['package_name']}")
                        print(f"\t{bcolors.FAIL}Package manager:{bcolors.ENDC} {item['package_manager']}")
                        print(f"\t{bcolors.FAIL}Version range:{bcolors.ENDC} {item['version_range']}")

                        if os.path.exists(stack_trace):
                            for trace in stack_array:
                                search_term = sym['class_name'] + "." + sym['method_name']
                                if search_term in trace:
                                    print(f"\t{bcolors.FAIL}Stack trace:{bcolors.ENDC}")
                                    print("\t", trace)
                                    break

        if (vuln_count == 0):
            print(f"{bcolors.OKGREEN}No vulnerable symbols found.{bcolors.ENDC}")

    except KeyboardInterrupt:
        print("EXITING ...")
        exit()
