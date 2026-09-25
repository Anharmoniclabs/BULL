#!/usr/bin/env python3
"""Install/check the fixed host dependencies used by the BULL Command Center."""
from __future__ import annotations
from pathlib import Path
import argparse, os, shutil, subprocess, sys

TOOLS=(
    ("clamav","ClamAV scanner","clamscan"),
    ("qemu","QEMU x86_64","qemu-system-x86_64"),
    ("mkfs","ext4 image builder","mkfs.ext4"),
    ("debugfs","ext4 inspection","debugfs"),
    ("openssl","OpenSSL","openssl"),
    ("ssh","OpenSSH key utility","ssh-keygen"),
)
PACKAGES={
    "apt":("clamav","clamav-freshclam","qemu-system-x86","qemu-utils","e2fsprogs","openssl","openssh-client"),
    "pacman":("clamav","qemu-full","e2fsprogs","openssl","openssh"),
    "dnf":("clamav","clamav-update","qemu-system-x86-core","qemu-img","e2fsprogs","openssl","openssh-clients"),
}

def manager():
    return "apt" if shutil.which("apt-get") else "pacman" if shutil.which("pacman") else "dnf" if shutil.which("dnf") else None

def clamav_databases():
    root=Path("/var/lib/clamav")
    if not root.is_dir(): return []
    out=[]
    for pattern in ("*.cvd","*.cld"):
        out.extend(str(p) for p in root.glob(pattern) if p.is_file())
    return sorted(out)

def state():
    items=[]
    for item_id,label,command in TOOLS:
        path=shutil.which(command)
        items.append({"id":item_id,"label":label,"command":command,"installed":bool(path),"path":path})
    db=clamav_databases()
    clamav=next(x for x in items if x["id"]=="clamav")
    clamav["database_ready"]=bool(db); clamav["database_count"]=len(db)
    return {"manager":manager(),"items":items,"missing":[x["id"] for x in items if not x["installed"]],"clamav_database_ready":bool(db),"clamav_database_count":len(db),"ready":all(x["installed"] for x in items) and bool(db)}

def prefix():
    if os.geteuid()==0: return []
    sudo=shutil.which("sudo")
    if not sudo: raise RuntimeError("root privileges or sudo are required to install host packages")
    probe=subprocess.run([sudo,"-n","true"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)
    if probe.returncode!=0: raise RuntimeError("passwordless sudo is unavailable; run the package-manager install manually")
    return [sudo,"-n"]

def run(command,required=True):
    print("+"," ".join(command),flush=True)
    proc=subprocess.run(command,check=False)
    if required and proc.returncode!=0: raise RuntimeError("host dependency command failed with exit code "+str(proc.returncode))
    return proc.returncode

def install():
    cur=state(); mgr=cur["manager"]
    if not mgr: raise RuntimeError("supported package manager not found (apt-get, pacman, or dnf)")
    if cur["missing"]:
        pfx=prefix(); packages=list(PACKAGES[mgr])
        if mgr=="apt":
            run(pfx+["apt-get","update"])
            run(pfx+["env","DEBIAN_FRONTEND=noninteractive","apt-get","install","-y",*packages])
        elif mgr=="pacman":
            run(pfx+["pacman","-S","--needed","--noconfirm",*packages])
        else:
            run(pfx+["dnf","install","-y",*packages])
    if not clamav_databases() and shutil.which("freshclam"):
        try: run(prefix()+[shutil.which("freshclam"),"--stdout"],required=False)
        except RuntimeError as exc: print("ClamAV database refresh skipped:",exc,file=sys.stderr)
    final=state()
    print("\nBULL HOST DEPENDENCIES")
    for item in final["items"]:
        extra=""
        if item["id"]=="clamav": extra=" | signatures="+("READY" if item.get("database_ready") else "MISSING")
        print(f"  {('READY' if item['installed'] else 'MISSING'):<8} {item['label']}{extra}")
    print("  RESULT  ", "READY" if final["ready"] else "PARTIAL")
    return 0 if final["ready"] else 1

def check():
    cur=state(); print("BULL HOST DEPENDENCIES"); print("  package manager:",cur["manager"] or "unsupported")
    for item in cur["items"]: print("  "+("READY   " if item["installed"] else "MISSING ")+item["label"])
    print("  "+("READY   " if cur["clamav_database_ready"] else "MISSING ")+"ClamAV signature database")
    return 0 if cur["ready"] else 1

def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument("--install",action="store_true"); a=p.parse_args()
    try: return install() if a.install else check()
    except Exception as exc: print("BULL host setup:",exc,file=sys.stderr); return 2

if __name__=="__main__": raise SystemExit(main())
