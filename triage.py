#!/usr/bin/env python3
'''
  Copyright (c) 2020, Andrea Fioraldi


  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright notice, this
     list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright notice,
     this list of conditions and the following disclaimer in the documentation
     and/or other materials provided with the distribution.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
'''

import subprocess
#import progressbar
import argparse
import shutil
import json
import sys
import os

HEADER = '\033[95m'
OKBLUE = '\033[94m'
OKGREEN = '\033[92m'
WARNING = '\033[93m'
FAIL = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'

DESCR = """Minimize set of crashing testcases using Sanitizers
Copyright (C) 2020 Andrea Fioraldi <andreafioraldi@gmail.com>
"""

dir_path = os.path.dirname(os.path.realpath(__file__))

opt = argparse.ArgumentParser(description=DESCR, formatter_class=argparse.RawTextHelpFormatter)
opt.add_argument('-i', action='append', help="Input directory with crashes", required=True)
opt.add_argument("-q", help="Be quiet", action='store_true')
opt.add_argument("-t", help="Sort by time not by size", action='store_true')
opt.add_argument("-s", help="Show program output runned with the minimized set", action='store_true')
opt.add_argument("-f", help="Input filename", action='store')
opt.add_argument("-c", help="Use crashing site, not stack hash (same as -n 1)", action='store_true')
opt.add_argument("-n", help="Specify the number of addresses from the top of the stacktrace to consider for the hash", action='store', type=int, default=-1)
opt.add_argument("-j", help="Save a bugs summary in json", action='store')
opt.add_argument("-r", help="Show bugs resume", action='store_true')
opt.add_argument("-R", help="Show bugs resume with stacktrace", action='store_true')
opt.add_argument('target', nargs=argparse.REMAINDER, help="Target program (and arguments)")

args = opt.parse_args()

be_quiet = args.q

os.environ["ASAN_OPTIONS"] = "detect_leaks=0:handle_segv=2:handle_sigill=2:handle_abort=2:handle_sigfpe=2"

def get_testcase_time(path):
    if "time:" in path:
        p = path[path.find("time:")+5:]
        t = ""
        for c in p:
            if c.isdigit(): t += c
            else: break
        return int(t)
    stat = os.stat(path)
    try:
        return stat.st_birthtime
    except AttributeError:
        return stat.st_mtime

def run(argv, stdin_file=None, print_output=False):
    if stdin_file:
        with open(stdin_file, "rb") as f:
            content = f.read()
    if print_output:
        p = subprocess.Popen(argv, stdin=subprocess.PIPE, close_fds=True)
        if stdin_file:
            p.stdin.write(content)
    else:
        p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True)
        if stdin_file:
            p.stdin.write(content)
        while(True):
            retcode = p.poll()
            yield p.stdout.readline()
            if retcode is not None:
                break
    p.wait()

def warn(x):
    global be_quiet
    if not be_quiet:
        sys.stdout.flush()
        print("\n" + WARNING + "[warning] " + x + ENDC)

def log_progress(x):
    global be_quiet
    if be_quiet:
        return x
    else:
        return progressbar.progressbar(x)

class UbsanCrash(object):
    def __init__(self, type_, loc, path, size):
        self.type = type_
        self.loc = loc
        self.path = path
        self.size = size
        self.time = get_testcase_time(path)
    def __hash__(self):
        return hash(self.loc)
    def __eq__(self, o):
        return self.loc == o.loc

class AsanCrash(object):
    def __init__(self, type_, trace, loc, path, size):
        self.type = type_
        self.trace = trace
        self.size = size
        self.loc = loc
        self.path = path
        self.time = get_testcase_time(path)
    def __hash__(self):
        return hash(tuple(self.trace))
    def __eq__(self, o):
        return self.trace == o.trace

def callstack_hash(s):
    l = list(s)
    if args.n >= 0:
        l = l[0:args.n]
    h = 0
    for a in l:
        h ^= a[0]
    return h

total_ubsan_bugs = {}
total_asan_bugs = {}

bugs_summary = {}

for dirpath in args.i:
    ubsan_bugs = {}
    asan_bugs = {}
    print (OKGREEN + " >>>> " + dirpath + ENDC)
    for fname in log_progress(os.listdir(dirpath)):
        path = os.path.join(dirpath, fname)
        size = os.path.getsize(path)
        argv = args.target[:]
        stdin_file = path
        for i in range(len(argv)):
            if argv[i] == "@@":
                argv[i] = path
                if args.f:
                    shutil.copy(argv[i], args.f)
                    argv[i] = args.f
                stdin_file = None
        errs = set()
        one_found = False
        start_asan = False
        in_trace = True
        stacktrace = []
        memaccess = ''
        first_st = None
        asan_type = ""
        for l in run(argv, stdin_file):
            if l.startswith(b"================================================================="):
                start_asan = True
            elif start_asan and b"ERROR: AddressSanitizer:" in l:
                l = l[l.find(b"ERROR: AddressSanitizer: ") + len(b"ERROR: AddressSanitizer: "):]
                asan_type = l.decode("utf-8")
            elif start_asan and b"ERROR: QEMU-AddressSanitizer:" in l:
                l = l[l.find(b"ERROR: QEMU-AddressSanitizer: ") + len(b"ERROR: QEMU-AddressSanitizer: "):]
                asan_type = l.decode("utf-8")
            elif start_asan and l.startswith(b'READ'):
                memaccess = 'read'
            elif start_asan and l.startswith(b'WRITE'):
                memaccess = 'write'
            elif (start_asan or in_trace) and l.startswith(b"    #"):
                in_trace = True
                start_asan = False
                ls = l.split()
                if first_st is None and b'libstdc++' not in l and b'/libc.' not in l and b'glibc' not in l:
                    first_st = (int(ls[1], 0), (b" ".join(ls[1:])).decode("utf-8"))
                if b'libstdc++' not in l and b'/libc.' not in l and b'glibc' not in l:
                    stacktrace.append((int(ls[1], 0), (b" ".join(ls[1:])).decode("utf-8")))
            elif in_trace:
                in_trace = False
            elif b": runtime error: " in l:
                l = l.split(b": runtime error: ")
                type_ = l[1].decode("utf-8")
                loc = l[0].decode("utf-8")
                errs.add(UbsanCrash(type_, loc, path, size))
                one_found = True
        #if not one_found and len(stacktrace) == 0:
            #warn(path + " does not trigger any violation!")
        if len(stacktrace) > 0:
            st = first_st
            etype = asan_type.split()[0]
            if not args.c and etype != 'ILL':
                st = callstack_hash(stacktrace)
            asan_bugs[(st, etype, memaccess)] = asan_bugs.get(st, []) + [AsanCrash(asan_type, stacktrace, first_st[1], path, size)]
        for c in errs:
            ubsan_bugs[c.loc] = ubsan_bugs.get(c.loc, []) + [c]

    total_ubsan_bugs[dirpath] = set()
    total_asan_bugs[dirpath] = set()

    term_w = 0
    for s in ubsan_bugs:
        total_ubsan_bugs[dirpath].add(s)
        if args.t:
            ubsan_bugs[s] = sorted(ubsan_bugs[s], key=lambda x: x.time)
        else:
            ubsan_bugs[s] = sorted(ubsan_bugs[s], key=lambda x: x.size)
        if args.j is not None:
            b = {}
            b["loc"] = s
            b["time"] = ubsan_bugs[s][0].time
            bugs_summary[dirpath] = bugs_summary.get(dirpath, [])
            bugs_summary[dirpath].append(b)
        if term_w == 0:
            term_w, _ = shutil.get_terminal_size((19 + max(len(ubsan_bugs[s][0].path), len(s)), 20))
        if args.r or args.R:
            print(HEADER + "=" * term_w + ENDC)
            print(BOLD + " Error type     : " + ubsan_bugs[s][0].type + ENDC)
            print(BOLD + " Error location : " + ubsan_bugs[s][0].loc + ENDC)
            print(BOLD + " Testcase path  : " + ubsan_bugs[s][0].path + ENDC)
            print(BOLD + " Testcase size  : " + str(ubsan_bugs[s][0].size) + ENDC)
            print(HEADER + "=" * term_w + ENDC)
        argv = args.target[:]
        stdin_file = ubsan_bugs[s][0].path
        for i in range(len(argv)):
            if argv[i] == "@@":
                argv[i] = ubsan_bugs[s][0].path
                if args.f:
                    shutil.copy(argv[i], args.f)
                    argv[i] = args.f
                stdin_file = None
        run(argv, stdin_file, args.s)

    for s in asan_bugs:
        total_asan_bugs[dirpath].add(s)
        if args.t:
            asan_bugs[s] = sorted(asan_bugs[s], key=lambda x: x.time)
        else:
            asan_bugs[s] = sorted(asan_bugs[s], key=lambda x: x.size)
        if args.j is not None:
            b = {}
            b["loc"] = s[0][0]
            b["time"] = asan_bugs[s][0].time
            bugs_summary[dirpath] = bugs_summary.get(dirpath, [])
            bugs_summary[dirpath].append(b)
        if term_w == 0:
            term_w, _ = shutil.get_terminal_size((19 + max(len(asan_bugs[s][0].path), len(asan_bugs[s][0].loc), len(asan_bugs[s][0].type)), 20))
        if args.r or args.R:
            print(HEADER + "=" * term_w + ENDC)
            print(BOLD + " Error type     : " + asan_bugs[s][0].type + ENDC)
            print(BOLD + " Error location : " + asan_bugs[s][0].loc + ENDC)
            print(BOLD + " Testcase path  : " + asan_bugs[s][0].path + ENDC)
            print(BOLD + " Testcase size  : " + str(asan_bugs[s][0].size) + ENDC)
            if args.R:
                print(BOLD + " Stacktrace     : " + ENDC)
                i = 0
                for addr, rep in asan_bugs[s][0].trace:
                    print('\t' + ('#'+str(i)).ljust(3, ' ') + ' ' + str(rep))
                    i += 1
            print(HEADER + "=" * term_w + ENDC)
        argv = args.target[:]
        stdin_file = asan_bugs[s][0].path
        for i in range(len(argv)):
            if argv[i] == "@@":
                argv[i] = asan_bugs[s][0].path
                if args.f:
                    shutil.copy(argv[i], args.f)
                    argv[i] = args.f
                stdin_file = None
        run(argv, stdin_file, args.s)

    print ("Unique UBSan violations :", len(ubsan_bugs))
    print ("Unique ASan violations  :", len(asan_bugs))
    print ()

print(OKBLUE + " >>>> Intersections" + ENDC)
already_intersected = []
for dirpath1 in total_ubsan_bugs.keys():
    for dirpath2 in total_ubsan_bugs.keys():
        if dirpath1 == dirpath2: continue
        if sorted((dirpath1, dirpath2)) in already_intersected: continue
        already_intersected.append(sorted((dirpath1, dirpath2)))
        print ("Intersection of UBSan violations for", dirpath1, "and", dirpath2, ":", len(total_ubsan_bugs[dirpath1].intersection(total_ubsan_bugs[dirpath2])))
        print ("Intersection of ASan violations for", dirpath1, "and", dirpath2, " :", len(total_asan_bugs[dirpath1].intersection(total_asan_bugs[dirpath2])))
print()

from functools import reduce

def median(l):
    if len(l) == 0:
        return 0
    if len(l) == 1:
        return l[0]
    l = sorted(l)
    if len(l) % 2 == 0:
        return (l[len(l)//2 -1] + l[len(l)//2]) / 2
    return l[len(l)//2]

def geo_mean(l):
    m = reduce(lambda x, y: x*y, l)
    return m**(1/len(l))

def mean(l):
    m = reduce(lambda x, y: x+y, l)
    return m / len(l)

print(OKBLUE + " >>>> Statistics" + ENDC)
print("Median of UBSan violations:", median(list(map(len, total_ubsan_bugs.values()))))
print("Median of ASan violations:", median(list(map(len, total_asan_bugs.values()))))

print("Mean of UBSan violations:", mean(list(map(len, total_ubsan_bugs.values()))))
print("Mean of ASan violations:", mean(list(map(len, total_asan_bugs.values()))))

print("Geo mean of UBSan violations:", geo_mean(list(map(len, total_ubsan_bugs.values()))))
print("Geo mean of ASan violations:", geo_mean(list(map(len, total_asan_bugs.values()))))

print()

if args.j is not None:
    with open(args.j, "w") as f:
        json.dump(bugs_summary, f)