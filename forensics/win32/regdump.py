#!/usr/bin/env python

from forensics.win32.rawreg import *
from forensics.win32.hive2 import HiveAddressSpace,HiveFileAddressSpace
from forensics.win32.datetime import windows_to_unix_time
from time import ctime
import csv

def dump_registry_hive(addr_space, out_fname, profile, hive_name="", include_vals=False):
    outf = open(out_fname, 'wb')
    out = csv.writer(outf)

    root = get_root(addr_space, profile)
    if hive_name != "": base = [hive_name]
    else: base = []

    if include_vals:
        header = ("timestamp","time_string","path","value_type","value")
    else:
        header = ("timestamp","time_string","path")
    out.writerow(header)

    # Try to buffer up writes
    row = 0
    rowbuf = []
    for key, path in reg_walk_fullpath(root, base):
        row += 1
        rowbuf.append( (windows_to_unix_time(key.LastWriteTime.QuadPart),
                        ctime(windows_to_unix_time(key.LastWriteTime.QuadPart)),
                        "\\".join(path)) )

        if not include_vals: continue
        for v in values(key):
            (tp, data) = value_string(v)
            
            name = v.Name if v.Name else "(default)"

            rowbuf.append( (windows_to_unix_time(key.LastWriteTime.QuadPart),
                            ctime(windows_to_unix_time(key.LastWriteTime.QuadPart)),
                            "\\".join(path + [name]),
                            tp, str(data)) )
        if row == 1024:
            # Flush
            out.writerows(rowbuf)
            del rowbuf[:]
            row = 0

    # Catch any stragglers
    out.writerows(rowbuf)
    outf.close()

def reg_walk_fullpath(root, base=[]):
    for k in subkeys(root):
        yield (k, base + [k.Name])
        for j in reg_walk_fullpath(k, base + [k.Name]):
            yield j

def mem_hive_keycounts(addr_space, types, hivelist):
    for h in hivelist:
        haddr = HiveAddressSpace(addr_space, types, h.offset)
        stb,vol = reg_count_keys(get_root(haddr,h.profile))
        print h.FileFullPath, stb, vol, stb+vol

def mem_hive_valcounts(addr_space, types, hivelist):
    for h in hivelist:
        haddr = HiveAddressSpace(addr_space, types, h.offset)
        stb,vol = reg_count_values(get_root(haddr,h.profile))
        print h.FileFullPath, stb, vol, stb+vol

def dsk_hive_keycounts(hivelist, profile):
    for h in hivelist:
        haddr = HiveFileAddressSpace(h)
        stb,vol = reg_count_keys(get_root(haddr, profile))
        print h, stb, vol, stb+vol

def dsk_hive_valcounts(hivelist, profile):
    for h in hivelist:
        haddr = HiveFileAddressSpace(h)
        stb,vol = reg_count_values(get_root(haddr, profile))
        print h, stb, vol, stb+vol

def reg_hivestats(addr_space, types, hivelist):
    for h in hivelist:
        haddr = HiveAddressSpace(addr_space, types, h.offset)
        print "Stable",h.FileFullPath
        haddr.stats(stable=True)
        print "-"*80
        print "Volatile",h.FileFullPath
        haddr.stats(stable=False)
        print "-"*80

def reg_count_keys(root):
    if not root.is_valid(): return 0,0
    vol_count = 0
    stb_count = 0
    for k in walk(root):
        if k.address & 0x80000000: vol_count += 1
        else: stb_count += 1
    return stb_count,vol_count

def reg_count_values(root):
    if not root.is_valid(): return 0,0
    vol_count = 0
    stb_count = 0
    for k in walk(root):
        for v in values(k):
            if v.address & 0x80000000: vol_count += 1
            else: stb_count += 1
    return stb_count,vol_count
