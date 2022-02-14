#!/usr/bin/python3
# @lint-avoid-python-3-compatibility-imports

import argparse
from datetime import datetime
from time import sleep
from bcc import BPF, USDT
import json
import os

# period
PERIOD = 10

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
args = parser.parse_args()

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
f = open('arvos_vfs.json')
vulnData = json.load(f)
f.close()

# Stack trace file
stack_trace = "/stack_logs/stack-traces.log"
with open(stack_trace) as f:
    stack_output = f.read()
# Load it into an array
stack_array = stack_output.split(os.linesep + os.linesep)


print("\nTracing Java calls in process %d and scanning for vulnerable symbols ... Ctrl-C to quit." % (args.pid))

# Loop until exit
while True:
    try:
        sleep(PERIOD)

        invoked_class_list = []
        invoked_method_list = []
    
        for k,v in bpf["counts"].items():
            invoked_class_list.append(k.clazz.decode('utf-8', 'replace').replace('/', '.'))
            invoked_method_list.append(k.method.decode('utf-8', 'replace'))


        for item in vulnData:
            for sym in item['symbols']:
                for i in range(len(invoked_class_list)):
                    if sym['class_name'] in invoked_class_list[i] and sym['method_name'] in invoked_method_list[i]:
                    
                        t_now = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")

                        print(f"\n{bcolors.FAIL}Vulnerable symbol invoked!!!")
                        print(f"\t{bcolors.FAIL}Time:{bcolors.ENDC} {t_now}")
                        print(f"\t{bcolors.FAIL}Vulnerability:{bcolors.ENDC} {item['vulnerability']}")
                        print(f"\t{bcolors.FAIL}Repository:{bcolors.ENDC} {item['repository']}")
                        print(f"\t{bcolors.FAIL}Invoked Class:{bcolors.ENDC} {sym['class_name']}")
                        print(f"\t{bcolors.FAIL}Invoked Method:{bcolors.ENDC} {sym['method_name']}")
                        print(f"\t{bcolors.FAIL}Confidence:{bcolors.ENDC} {item['confidence']}")
                        print(f"\t{bcolors.FAIL}Spread:{bcolors.ENDC} {item['spread']}")

                        for trace in stack_array:
                            search_term = sym['class_name'] + "." + sym['method_name']
                            if search_term in trace:
                                print(f"\t{bcolors.FAIL}Stack trace:{bcolors.ENDC}")
                                print("\t", trace)
                                break

    except KeyboardInterrupt:
        print("EXITING ...")
        exit()
