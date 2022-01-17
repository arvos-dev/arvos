#! /usr/bin/python3

from __future__ import print_function
import argparse
from bcc import BPF, USDT, utils
import ctypes as ct
import csv
from datetime import datetime
import time
import json
import pandas as pd
import multiprocessing as mp
import os

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


class CallEvent(ct.Structure):
    _fields_ = [
        ("depth", ct.c_ulonglong),
        ("pid", ct.c_ulonglong),
        ("clazz", ct.c_char * 128),
        ("method", ct.c_char * 128)
    ]

def readResults():

    # period
    PERIOD = 10
    # Vulnerability db
    f = open('arvos_vfs.json')
    vulnData = json.load(f)
    f.close()
    dfVuln = pd.DataFrame(vulnData)

    # Invoked classes and methods
    invokedClassesFile = 'invoked_classes.csv'

    while not os.path.exists(invokedClassesFile):
        print(f"{bcolors.WARNING}Waiting for scanning to start ...{bcolors.ENDC}")
        time.sleep(1)

    print(f"{bcolors.OKGREEN}Scanning is now started.")
    print(f"{bcolors.OKGREEN}Please wait patiently until we gather the results ...{bcolors.ENDC}")

    while 1:
        try:
            dfInvoked = pd.read_csv(invokedClassesFile, header=None)
            dfInvoked.columns = ['time', 'clazz', 'method']

            dfInvoked['timestamp'] = dfInvoked['time'].apply(lambda x: pd.Timestamp(x))

            last_ts = dfInvoked['timestamp'].iloc[-1]
            first_ts = last_ts - pd.Timedelta(PERIOD, 'seconds')
            filtered_df = dfInvoked[dfInvoked['timestamp'] >= first_ts]

            # Compare
            for index, row in dfVuln.iterrows():
                for item in row['symbols']:
                    class_name = item['class_name'].replace('.', '/')
                    method_name = item['method_name']
                    dfClass = filtered_df[filtered_df['clazz'].str.contains(class_name)]
                    dfMethod = dfClass[dfClass['method'].str.contains(method_name)]
                    if len(dfMethod) > 0:
                        for i, r in dfMethod.iterrows():
                            print(f"{bcolors.FAIL}Vulnerability found!!!")
                            print(f"\t{bcolors.FAIL}Time:{bcolors.ENDC} {r['time']}")
                            print(f"\t{bcolors.FAIL}Vulnerability:{bcolors.ENDC} {row['vulnerability']}")
                            print(f"\t{bcolors.FAIL}Repository:{bcolors.ENDC} {row['repository']}")
                            print(f"\t{bcolors.FAIL}Invoked Class:{bcolors.ENDC} {row['symbols'][0]['class_name']}")
                            print(f"\t{bcolors.FAIL}Invoked Method:{bcolors.ENDC} {row['symbols'][0]['method_name']}")
                            print(f"\t{bcolors.FAIL}Confidence:{bcolors.ENDC} {row['confidence']}")
                            print(f"\t{bcolors.FAIL}Spread:{bcolors.ENDC} {row['spread']}")
            time.sleep(PERIOD)
        except KeyboardInterrupt:
            print("EXITING ....")
            exit()

def print_event(cpu, data, size):
    # get event
    event = ct.cast(data, ct.POINTER(CallEvent)).contents
    invokedClass = event.clazz.decode('utf-8', 'replace')
    invokedMethod = event.method.decode('utf-8', 'replace')

    output = [datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S"), invokedClass, invokedMethod]

    with open('invoked_classes.csv', 'a', encoding='UTF8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(output)


def run_uflow(pid):
    clazz = ""
    method = ""

    program = """
    struct call_t {
        u64 depth;                  // first bit is direction (0 entry, 1 return)
        u64 pid;                    // (tgid << 32) + pid from bpf_get_current...
        char clazz[128];
        char method[128];
    };

    BPF_PERF_OUTPUT(calls);
    BPF_HASH(entry, u64, u64);
    """

    prefix_template = """
    static inline bool prefix_%s(char *actual) {
        char expected[] = "%s";
        for (int i = 0; i < sizeof(expected) - 1; ++i) {
            if (expected[i] != actual[i]) {
                return false;
            }
        }
        return true;
    }
    """

    if clazz:
        program += prefix_template % ("class", clazz)
    if method:
        program += prefix_template % ("method", method)

    trace_template = """
    int NAME(struct pt_regs *ctx) {
        u64 *depth, zero = 0, clazz = 0, method = 0 ;
        struct call_t data = {};

        READ_CLASS
        READ_METHOD
        bpf_probe_read(&data.clazz, sizeof(data.clazz), (void *)clazz);
        bpf_probe_read(&data.method, sizeof(data.method), (void *)method);

        FILTER_CLASS
        FILTER_METHOD

        data.pid = bpf_get_current_pid_tgid();
        depth = entry.lookup_or_try_init(&data.pid, &zero);
        if (!depth) {
            depth = &zero;
        }
        data.depth = DEPTH;
        UPDATE

        calls.perf_submit(ctx, &data, sizeof(data));
        return 0;
    }
    """

    usdt = USDT(pid=pid)

    probe_name = "method__entry"
    func_name = "java_entry"
    read_class = "bpf_usdt_readarg(2, ctx, &clazz);"
    read_method = "bpf_usdt_readarg(4, ctx, &method);"
    is_return = False

    # global program, trace_template, usdt
    depth = "*depth + 1" if not is_return else "*depth | (1ULL << 63)"
    update = "++(*depth);" if not is_return else "if (*depth) --(*depth);"
    filter_class = "if (!prefix_class(data.clazz)) { return 0; }" \
        if clazz else ""
    filter_method = "if (!prefix_method(data.method)) { return 0; }" \
        if method else ""
    program += trace_template.replace("NAME", func_name) \
        .replace("READ_CLASS", read_class) \
        .replace("READ_METHOD", read_method) \
        .replace("FILTER_CLASS", filter_class) \
        .replace("FILTER_METHOD", filter_method) \
        .replace("DEPTH", depth) \
        .replace("UPDATE", update)

    usdt.enable_probe_or_bail(probe_name, func_name)

    bpf = BPF(text=program, usdt_contexts=[usdt])

    bpf["calls"].open_perf_buffer(print_event, page_cnt=8192)

    while 1:
        try:
            bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            print("EXITING ....")
            exit()

examples = """examples:
    ./arvos-poc 185                # trace Java method calls in process 185
"""

parser = argparse.ArgumentParser(
    description="Trace method execution flow in Java.",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("pid", type=int, help="process id to attach to")
args = parser.parse_args()
pid = args.pid

# Multi-processing

p = mp.Process(target=run_uflow, args=(pid,))
q = mp.Process(target=readResults)
p.start()
q.start()
p.join()
q.join()