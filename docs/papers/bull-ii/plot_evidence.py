"""Generate publication plots only from hashed, retained BULL evidence."""
import csv
import re
from pathlib import Path

def extra_figures(root: Path, dest: Path):
    import matplotlib.pyplot as plt
    import numpy as np
    plt.rcParams.update({'font.family':'DejaVu Sans','font.size':9,'pdf.fonttype':42,
                         'axes.spines.top':False,'axes.spines.right':False})
    def save(fig,name):
        fig.savefig(dest/(name+'.pdf'),bbox_inches='tight',metadata={'CreationDate':None,'ModDate':None})
        plt.close(fig)
    def grid(ax):
        ax.xaxis.grid(True,color='#dce5e7',linewidth=.6);ax.set_axisbelow(True)
    folder=root/'evidence/site/data/benchmarks/20260920'
    with (folder/'attack-summary.csv').open() as f: rows=list(csv.DictReader(f))
    assert len(rows)==11 and sum(int(x['runs']) for x in rows)==33
    mean=np.array([float(x['mean_ms']) for x in rows]);lo=np.array([float(x['min_ms']) for x in rows]);hi=np.array([float(x['max_ms']) for x in rows])
    fig,ax=plt.subplots(figsize=(7.15,3.8),layout='constrained')
    ax.errorbar(mean,range(len(rows)),xerr=[mean-lo,hi-mean],fmt='o',color='#16776d',capsize=3)
    ax.set_yticks(range(len(rows)),[x['attack'].replace('→','to') for x in rows],fontsize=8)
    ax.invert_yaxis();ax.set_xlim(270,435)
    for i,v in enumerate(mean):ax.text(402,i,f'{v:.3f}',va='center',fontsize=8)
    ax.set_xlabel('Mean pytest duration and recorded min–max (milliseconds)');grid(ax);save(fig,'defensive-corpus')
    with (folder/'hotpath.csv').open() as f: rows=list(csv.DictReader(f))
    assert all(int(x['iterations'])==500 for x in rows)
    fig,ax=plt.subplots(figsize=(7.15,2.15),layout='constrained')
    vals=[float(x['mean_us']) for x in rows]
    ax.scatter(vals,range(len(vals)),color=['#16776d','#a5712b','#a5712b'],s=34)
    ax.set_yticks(range(len(vals)),[x['benchmark'] for x in rows],fontsize=8)
    ax.invert_yaxis();ax.set_ylim(2.5,-.5);ax.set_xscale('log');ax.set_xlim(1,4e6)
    for i,v in enumerate(vals):ax.annotate(f'{v:,.3f}',(v,i),xytext=(7,0),textcoords='offset points',va='center',fontsize=8)
    ax.set_xlabel('Mean microseconds per operation (log scale)');grid(ax);save(fig,'hotpath-results')
    text=(root/'evidence/docs/MICROVM_INTEGRATION_REPORT.md').read_text()
    block=text.split('## Measured allowed run',1)[1].split('These are one-run',1)[0]
    rows=re.findall(r'^\| (.*?) \| ([0-9.]+) \|$',block,re.M)
    assert len(rows)==9
    labels=['QEMU start to dispatcher ready','Launcher to dispatcher ready','Guest runtime / dispatcher init','Dispatch, including admission + scan','Sandbox setup to pre-exec','Pre-exec to process reap','Deterministic fixture body','Completion audit acknowledgment','Result / audit outside dispatch']
    vals=[float(v) for _,v in rows]
    fig,ax=plt.subplots(figsize=(7.15,3.6),layout='constrained')
    ax.scatter(vals,range(len(vals)),color='#16776d',s=30)
    ax.set_yticks(range(len(vals)),labels,fontsize=8);ax.invert_yaxis();ax.set_xscale('log');ax.set_xlim(.1,1.3e5)
    for i,v in enumerate(vals):ax.annotate(f'{v:,.3f}',(v,i),xytext=(7,0),textcoords='offset points',va='center',fontsize=8)
    ax.set_xlabel('Single observed interval (milliseconds; log scale)');grid(ax);save(fig,'kvm-results')
