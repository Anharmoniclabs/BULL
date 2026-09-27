#!/usr/bin/env python3
"""Original, reproducible diagrams from the paper's scoped evidence ledger."""
import json
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

HERE = Path(__file__).resolve().parent
DATA = json.loads((HERE / "evidence.json").read_text())
OUT = HERE / "figures"
OUT.mkdir(exist_ok=True)
NAVY, TEAL, AMBER, GRAY = "#17324d", "#007e83", "#d08735", "#667584"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10,
                     "figure.facecolor": "white", "axes.spines.top": False,
                     "axes.spines.right": False})

def box(ax, xy, wh, title, detail, fill="#eef4f7", edge=NAVY):
    x,y = xy; w,h = wh
    ax.add_patch(FancyBboxPatch((x,y),w,h,boxstyle="round,pad=0.015,rounding_size=0.025",
                                facecolor=fill,edgecolor=edge,linewidth=1.4))
    ax.text(x+w/2,y+h*.64,title,ha="center",va="center",fontweight="bold",color=NAVY,fontsize=11)
    ax.text(x+w/2,y+h*.31,detail,ha="center",va="center",color=NAVY,fontsize=8.4,linespacing=1.4)

fig,ax=plt.subplots(figsize=(11.2,4.15)); ax.set(xlim=(0,11),ylim=(0,4)); ax.axis("off")
box(ax,(.12,1.6),(1.8,1.4),"Agent proposal","untrusted text\nand tool request",fill="#fff4e7",edge=AMBER)
box(ax,(2.38,1.6),(2.3,1.4),"Host authority","exact action, grant,\nadmitted bytes")
box(ax,(5.15,1.6),(2.25,1.4),"Contained action","namespaces or fresh\nKVM guest")
box(ax,(7.88,1.6),(2.75,1.4),"Bounded result","broker decision, receipt,\naudit checkpoint")
for x1,x2 in [(1.94,2.35),(4.7,5.12),(7.42,7.85)]:
    ax.add_patch(FancyArrowPatch((x1,2.3),(x2,2.3),arrowstyle="-|>",mutation_scale=15,linewidth=2,color=TEAL))
ax.text(5.4,.8,"The model can propose. Host-owned checks decide what executes and what result is trusted.",
        ha="center",color=GRAY,fontsize=10)
fig.savefig(OUT/"authority_boundary.png",dpi=300,bbox_inches="tight"); plt.close(fig)

fig,ax=plt.subplots(figsize=(10.5,4.6)); ax.axis("off"); ax.set(xlim=(0,10),ylim=(0,4.6))
box(ax,(.25,1.25),(4.3,2.4),"Pinned offline guest","Buildroot · fresh one-shot KVM\nQEMU -net none · outbound sockets denied\n5 cases + separate offline probe",fill="#e5f4f1",edge=TEAL)
box(ax,(5.45,1.25),(4.3,2.4),"Networked candidate","Disposable Debian KVM guest\nbullgw + nftables + systemd units\n12 scoped checks passed",fill="#ecf1f7",edge=NAVY)
ax.text(5,.38,"Different images and boot paths: passing each side does not test their production combination.",
        ha="center",fontsize=10,color=AMBER,fontweight="bold")
fig.savefig(OUT/"two_guest_paths.png",dpi=300,bbox_inches="tight"); plt.close(fig)

items=DATA["series"]
fig,ax=plt.subplots(figsize=(10,4.5))
ys=list(range(len(items)))[::-1]
ax.barh(ys,[x["total"] for x in items],color="#e4ebef",height=.54)
ax.barh(ys,[x["passed"] for x in items],color=[TEAL,TEAL,NAVY,NAVY],height=.54)
ax.set_yticks(ys,[x["label"] for x in items]); ax.set_xlim(0,14.2)
ax.set_xlabel("Checks passed within each distinct fixture (not pooled)")
ax.grid(axis="x",alpha=.18); ax.set_axisbelow(True)
for y,x in zip(ys,items):
    ax.text(x["total"]+.25,y,f'{x["passed"]}/{x["total"]}  ·  {x["commit"]}',va="center",fontsize=9,color=NAVY)
fig.tight_layout(); fig.savefig(OUT/"scoped_results.png",dpi=300,bbox_inches="tight"); plt.close(fig)
