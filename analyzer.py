#!/usr/bin/env python3
'''
  Copyright (c) 2023, Tiziano Colagrossi


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
import matplotlib.patches as mpatches
from matplotlib.lines import Line2D
from statistics import mean,median, stdev
from rich.console import Console
import matplotlib.pyplot as plt
from rich.table import Table
from zipfile import ZipFile
import argparse
import tempfile
import shutil
import glob
import os

def check_all_eq(list):
    return True if len(set(list)) <= 1 else False

def str_to_num(ins):
    if ins[-1]=='%':
        ins=ins[:-1]
    try:
        return int(ins)
    except:
        try:
            return float(ins)
        except:
            return ins
        
def is_num(ins):
    try:
        int(ins)
        return True
    except:
        try:
            float(ins)
            return True
        except:
            return False

console = Console()

parser = argparse.ArgumentParser()
parser.add_argument("directory", help="select directory with zipped output afl++ dirs")
args = parser.parse_args()

#print(args.directory)
if not os.path.isdir(args.directory):
    console.log(f"Error: {args.directory} not found")
    quit()

console.log(f"parsing directory {args.directory}")


files = os.listdir(args.directory)
console.log("files found: ",files)
tmpdir = tempfile.mkdtemp()

console.print(tmpdir)

for index, fzip in enumerate(files):
#console.log(tempfile.gettempdir())
    with ZipFile(os.path.join(args.directory, fzip), 'r') as zObject:
        if "baseline" in fzip.lower():
            index = f"baseline_{index}"
        zObject.extractall(os.path.join(tmpdir, f"output_{index}"))

stats_files_path = glob.glob(tmpdir + "/**/fuzzer_stats", recursive = True)
console.print(stats_files_path)

plotdata_files_path = glob.glob(tmpdir + "/**/plot_data", recursive = True)
console.print(plotdata_files_path)

stats_baseline = {}
stats_cmp_run  = {}


for stat_path in stats_files_path:
    dict_selected = stats_baseline if 'baseline' in stat_path.lower() else stats_cmp_run
    with open(stat_path) as infd:
        lines = infd.readlines()
        for l in lines:
            name, value = l.replace('\n','').split(':')
            name, value = name.strip(), str_to_num(value.strip().replace('%',''))
            #console.print(name, value)
            if name not in dict_selected:
                dict_selected[name] = []
            dict_selected[name] += [value]


#console.print(stats_baseline)
#console.print(stats_cmp_run)

if not check_all_eq(stats_cmp_run['target_mode']+stats_baseline['target_mode']):
    console.log("Error not all runs equal to baseline a")
if not check_all_eq(stats_cmp_run['afl_banner']+stats_baseline['afl_banner']):
    console.log("Error not all runs equal to baseline b")
if not check_all_eq(stats_cmp_run['afl_version']+stats_baseline['afl_version']):
    console.log("Error not all runs equal to baseline c")

table = Table(title=f"Comparison output {args.directory}")

table.add_column("Data", justify="left", style="green", no_wrap=True)
table.add_column("baseline", justify="left", no_wrap=True)
table.add_column("runs median", justify="left", no_wrap=True)
table.add_column("diff", justify="left", no_wrap=True)
table.add_column("diff%", justify="left", no_wrap=True)
table.add_column("Data", justify="right", style="green", no_wrap=True)


#console.print(stats_baseline)

show_stats = ['cycles_done', 'cycles_wo_finds', 'execs_done', 'execs_per_sec', 'corpus_count', 
              'corpus_favored', 'corpus_found','max_depth','pending_favs', #'pending_total', 
              'stability', 'bitmap_cvg', 'saved_crashes', 'saved_hangs', 'edges_found','total_edges',
              'testcache_size', 'testcache_count' ]

for k in stats_baseline:
    if k not in show_stats:
        continue
    try:
        sb_median = median(stats_baseline[k])
        sr_median = median(stats_cmp_run[k])
        diff = sr_median - sb_median
        # diff/base=x/100
        perc = 0.0
        if(sb_median!=0):
            perc = (diff/sb_median)*100

        pre_diff = "R Eq B "
        if diff != 0:
            pre_diff = "R less " if diff < 0 else "R more "
        table.add_row(k, f'{sb_median:.3f}', f'{sr_median:.3f}', f'{pre_diff} {abs(diff):.3f}', f'{"+"if perc>=0 else ""}{perc:.3f}%',k )

        print()
    except:
        print(k, 'err')
        continue
    #print(k, median(stats_baseline[k]), median(stats_cmp_run[k]))

console.print(table)

csv_files_plot = {}

plot_baseline = {}
plot_cmp_run  = {}

for plot_path in plotdata_files_path:
    dict_selected = {}
    with open(plot_path) as infd:
        lines = infd.readlines()
        plot_keys = lines[0][2:].strip().split(', ')
        #console.print(plot_keys)
        for k in plot_keys:
            if k not in dict_selected:
                dict_selected[k]=[]

        for l in lines[1:]:
            for index, value in enumerate(l.strip().split(', ')):
            # # relative_time, cycles_done, cur_item, corpus_count, pending_total, pending_favs, map_size, saved_crashes, saved_hangs, max_depth, execs_per_sec, total_execs, edges_found
                try:
                    dict_selected[plot_keys[index]]+=[str_to_num(value)]
                except:
                    continue
    csv_files_plot[plot_path]=dict_selected
    

console.print(len(csv_files_plot))

for d in csv_files_plot:
    if 'baseline' in d.lower():
        plt.plot(csv_files_plot[d]['relative_time'],csv_files_plot[d]['pending_total'],label = "pending_total B", color="blue")
        # plt.plot(csv_files_plot[d]['relative_time'],csv_files_plot[d]['pending_favs'],label = "pending_favs B")
        # plt.plot(csv_files_plot[d]['relative_time'],csv_files_plot[d]['cycles_done'],label = "cycles_done B")
        # plt.plot(csv_files_plot[d]['relative_time'],csv_files_plot[d]['saved_crashes'],label = "saved_crashes B")
        # plt.plot(csv_files_plot[d]['relative_time'],csv_files_plot[d]['saved_hangs'],label = "saved_hangs B")
        # plt.plot(csv_files_plot[d]['relative_time'],csv_files_plot[d]['max_depth'],label = "max_depth B")
        plt.fill_between(csv_files_plot[d]['relative_time'],csv_files_plot[d]['corpus_count'], alpha=0.4,color="blue")
        # plt.fill_between(csv_files_plot[d]['relative_time'],csv_files_plot[d]['cur_item'], alpha=0.1,color="cyan")
        plt.fill_between(csv_files_plot[d]['relative_time'],csv_files_plot[d]['saved_crashes'], alpha=0.4,color="black")
        # plt.show()


    else:
        plt.plot(csv_files_plot[d]['relative_time'],csv_files_plot[d]['pending_total'],label = f"pending_total", color="orange")
        # plt.plot(csv_files_plot[d]['relative_time'],csv_files_plot[d]['pending_favs'],label = f"pending_favs")
        # plt.plot(csv_files_plot[d]['relative_time'],csv_files_plot[d]['cycles_done'],label = f"cycles_done")
        # plt.plot(csv_files_plot[d]['relative_time'],csv_files_plot[d]['saved_crashes'],label = f"saved_crashes")
        # plt.plot(csv_files_plot[d]['relative_time'],csv_files_plot[d]['saved_hangs'],label = f"saved_hangs")
        # plt.plot(csv_files_plot[d]['relative_time'],csv_files_plot[d]['max_depth'],label = f"max_depth")
        plt.fill_between(csv_files_plot[d]['relative_time'],csv_files_plot[d]['corpus_count'], alpha=0.4, color="orange")
        # plt.fill_between(csv_files_plot[d]['relative_time'],csv_files_plot[d]['cur_item'], alpha=0.1, color="yellow")
        plt.fill_between(csv_files_plot[d]['relative_time'],csv_files_plot[d]['saved_crashes'], alpha=0.4,color="red")
        # plt.show()
        
scb = Line2D([0], [0],color='red', label='saved_crashes runs')
scr = Line2D([0], [0],color='black', label='saved_crashes baseline')
ptr = Line2D([0], [0],color='blue', label='pending_total baseline')
ptb = Line2D([0], [0],color='orange', label='pending_total runs')

ccb = mpatches.Patch(color='blue', label='corpus_count baseline')
ccr = mpatches.Patch(color='orange', label='corpus_count runs')

plt.title(args.directory)
plt.legend(handles=[scb, scr,ptr,ptb,ccb,ccr])
# # show a legend on the plot
# plt.legend()
# # function to show the plot
plt.show()

# console.print(plot_baseline)
# console.print(plot_cmp_run)

print('deletng')
shutil.rmtree(tmpdir, ignore_errors=True)
print('deletng end')
