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
import arthas
import requests
import ray

TRACE_TIME = int(os.getenv('TRACE_TIME', 1)) * 6
# period
PERIOD = 10
ENDPOINT = "http://localhost:8563/api"
STACKS_DIR = "/stacks"
ray.init()

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
                    if len(set(vuln['package_version_range'].values())) == 1 and set(vuln['package_version_range'].values().pop() == "~"):
                        version_range = list(filter(lambda e: e[1] != '~', list(vuln['cpe_version_range'].items())))
                    else :
                        version_range = list(filter(lambda e: e[1] != '~', list(vuln['package_version_range'].items())))
                    specifier_set = ",".join(list(map(lambda e: operators[e[0]] + e[1],version_range)))
                    if not package_version in SpecifierSet(specifier_set):
                        print("%s not  %s" % (package_version, specifier_set))
                        indices_to_be_deleted.append(index)
    for i in sorted(indices_to_be_deleted, reverse=True):
        del db[i]
    return db

@ray.remote
def pull_results(art):
  gotResults = False
  while not gotResults:
    r = requests.post(ENDPOINT, json={'action': 'pull_results', 'sessionId': art.sessionId, 'consumerId': art.consumerId})
    if r.json()['state'] == "SUCCEEDED":
        if len(r.json()['body']['results']) > 0:
          for result in r.json()['body']['results']:
            if result['jobId'] == 0 :
              continue
            if result['type'] == 'status' and result['statusCode'] == -1:
              print("Skipping symbol %s as it was not loaded in the JVM" % ".".join(art.command.split(" ")[1:]))
              gotResults = True
              art.interrupt_job()
              art.close_session()
            if result['jobId'] != 0  and result['type'] == "stack":
              gotResults = True
              with open(f"%s/%s.stack" % (STACKS_DIR, ".".join(art.command.split(" ")[1:])), "w") as f:
                  for stacktrace in result['stackTrace'] :
                    if 'fileName' in stacktrace.keys():
                      f.write("at %s.%s(%s:%s) \n" % (stacktrace['className'], stacktrace['methodName'], stacktrace['fileName'], stacktrace['lineNumber']))
              art.interrupt_job()
              art.close_session()
              break
        else :
          sleep(2)
    else :
      raise RuntimeError(r.json()['message'])


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
    vuln_obj = json.loads(data)
else :
    vuln_obj = filter_relevant_vulnerabilities(json.loads(data), dep_list)


# keep track of invoked vulnerable symbols
vuln_count = 0

print(f"{bcolors.OKGREEN}\nTracing Java calls in process %d and scanning for vulnerable symbols ... Ctrl-C to quit.{bcolors.ENDC}" % (args.pid))

# Loop until exit
seen  = []
parallel_functions  = []
opened_sessions = []

while TRACE_TIME != 0:
    TRACE_TIME -= 1 
    sleep(PERIOD)

    invoked_class_list = []
    invoked_method_list = []

    for k,v in bpf["counts"].items():
        invoked_class_list.append(k.clazz.decode('utf-8', 'replace').replace('/', '.'))
        invoked_method_list.append(k.method.decode('utf-8', 'replace'))
    
    for i in range(len(invoked_class_list)):
        for item in vuln_obj:
            for sym in item['symbols']:
                if sym['class_name'] in invoked_class_list[i] and sym['method_name'] in invoked_method_list[i]:
                    traced = sym['class_name'] + " " + sym['method_name']
                    if not traced in seen :
                        vuln_count += 1 
                        art = arthas.Arthas()
                        art.async_exec("stack %s" % traced)
                        seen.append(traced)
                        ref = pull_results.remote(art)
                        parallel_functions.append(ref)


print("Closing all arthas sessions..")
for session in opened_sessions:
    arthas.Arthas.close_session(session)

print("Generating Report ...")

for stackfile in os.listdir(STACKS_DIR):
  f = os.path.join(STACKS_DIR, stackfile)
  symbol = stackfile[:-6]
  class_name = ".".join(symbol.split('.')[:-1])
  method_name = symbol.split('.')[-1]
  for item in vuln_obj:
    for sym in item['symbols']:
      if class_name == sym['class_name'] and method_name == sym['method_name']:
        print(f"\n{bcolors.FAIL}Vulnerable symbol invoked!!!")
        print(f"\t{bcolors.FAIL}Vulnerability:{bcolors.ENDC} {item['vulnerability']}")
        print(f"\t{bcolors.FAIL}Repository:{bcolors.ENDC} {item['repository']}")
        print(f"\t{bcolors.FAIL}Invoked Class:{bcolors.ENDC} {sym['class_name']}")
        print(f"\t{bcolors.FAIL}Invoked Method:{bcolors.ENDC} {sym['method_name']}")
        print(f"\t{bcolors.FAIL}Confidence:{bcolors.ENDC} {item['confidence']}")
        print(f"\t{bcolors.FAIL}Spread:{bcolors.ENDC} {item['spread']}")
        print(f"\t{bcolors.FAIL}Package name:{bcolors.ENDC} {item['package_name']}")
        print(f"\t{bcolors.FAIL}Package manager:{bcolors.ENDC} {item['package_manager']}")
        print(f"\t{bcolors.FAIL}Version range:{bcolors.ENDC} {item['package_version_range']}")
        print(f"\t{bcolors.FAIL}Stack trace:{bcolors.ENDC}")
        print("\t", open(f).read())
        print("------------------------------------------------------------------------------")


