# Volatility
# Copyright (c) 2008 Volatile Systems
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#

"""
@author:       Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      bdolangavitt@wesleyan.edu
"""

from forensics.object2 import Object
from forensics.object import read_value
from struct import unpack

_DEFAULTS = {
    "REG_NONE": "",
    "REG_SZ": "",
    "REG_EXPAND_SZ": "",
    "REG_BINARY": "",
    "REG_DWORD": 0,
    "REG_DWORD_BIG_ENDIAN": 0,
    "REG_LINK": "",
    "REG_MULTI_SZ": [],
    "REG_RESOURCE_LIST": "",
    "REG_FULL_RESOURCE_DESCRIPTOR": "",
    "REG_RESOURCE_REQUIREMENTS_LIST": "",
    "REG_QWORD": 0,
}

ROOT_INDEX = 0x20
LH_SIG = unpack("<H","lh")[0]
LF_SIG = unpack("<H","lf")[0]
RI_SIG = unpack("<H","ri")[0]
NK_SIG = unpack("<H","nk")[0]
VK_SIG = unpack("<H","vk")[0]

KEY_FLAGS = {
    "KEY_IS_VOLATILE"   : 0x01,
    "KEY_HIVE_EXIT"     : 0x02,
    "KEY_HIVE_ENTRY"    : 0x04,
    "KEY_NO_DELETE"     : 0x08,
    "KEY_SYM_LINK"      : 0x10,
    "KEY_COMP_NAME"     : 0x20,
    "KEY_PREFEF_HANDLE" : 0x40,
    "KEY_VIRT_MIRRORED" : 0x80,
    "KEY_VIRT_TARGET"   : 0x100,
    "KEY_VIRTUAL_STORE" : 0x200,
}

VALUE_TYPES = dict(enumerate([
    "REG_NONE",
    "REG_SZ",
    "REG_EXPAND_SZ",
    "REG_BINARY",
    "REG_DWORD",
    "REG_DWORD_BIG_ENDIAN",
    "REG_LINK",
    "REG_MULTI_SZ",
    "REG_RESOURCE_LIST",
    "REG_FULL_RESOURCE_DESCRIPTOR",
    "REG_RESOURCE_REQUIREMENTS_LIST",
    "REG_QWORD",
]))
VALUE_TYPES.setdefault("REG_UNKNOWN")

BIG_DATA_MAGIC = 0x3fd8

def get_root(address_space,profile,stable=True):
    if stable:
        return Object("_CM_KEY_NODE", ROOT_INDEX, address_space, profile=profile)
    else:
        return Object("_CM_KEY_NODE", ROOT_INDEX | 0x80000000, address_space, profile=profile)

def open_key(root, key):
    if key == []:
        return root

    if not root.is_valid():
        return None
    
    keyname = key.pop(0)
    for s in subkeys(root):
        if s.Name.upper() == keyname.upper():
            return open_key(s, key)
    #print "ERR: Couldn't find subkey %s of %s" % (keyname, root.Name)
    return None

def read_sklist(sk):
    sub_list = []
    if (sk.Signature == LH_SIG or
        sk.Signature == LF_SIG):
        return sk.List
    elif sk.Signature == RI_SIG:
        l = []
        for i in range(sk.Count):
            # Read and dereference the pointer
            ptr_off = sk.get_member_offset('List')+(i*4)
            if not sk.vm.is_valid_address(ptr_off): continue
            ssk_off = read_value(sk.vm, "unsigned int", ptr_off)
            if not sk.vm.is_valid_address(ssk_off): continue
            
            ssk = Object("_CM_KEY_INDEX", ssk_off, sk.vm, profile=sk.profile)
            l += read_sklist(ssk)
        return l
    else:
        return []

# Note: had to change SubKeyLists to be array of 2 pointers in vtypes.py
def subkeys(key):
    if not key.is_valid(): return []
    sub_list = []
    if key.SubKeyCounts[0] > 0:
        sk_off = key.SubKeyLists[0]
        sk = Object("_CM_KEY_INDEX", sk_off, key.vm, profile=key.profile)
        if not sk or not sk.is_valid():
            pass
        else:
            sub_list += read_sklist(sk)
    if key.SubKeyCounts[1] > 0:
        sk_off = key.SubKeyLists[1]
        sk = Object("_CM_KEY_INDEX", sk_off, key.vm, profile=key.profile)
        if not sk or not sk.is_valid():
            pass
        else:
            sub_list += read_sklist(sk)

    #sub_list = [s.value for s in sub_list]
    return [ s for s in sub_list if 
             s.is_valid() and s.Signature == NK_SIG]

def values(key):
    return [ v for v in key.ValueList.List
             if v.is_valid() and
             v.Signature == VK_SIG ]

def key_flags(key):
    return [ k for k in KEY_FLAGS if key.Flags & KEY_FLAGS[k] ]

def value_data(val):
    """Return a tuple of type, data representing the decoded value data"""
    try:
        valtype = VALUE_TYPES[val.Type]
    except KeyError:
        valtype = "REG_UNKNOWN_%X" % val.Type

    inline =  val.DataLength & 0x80000000

    if inline:
        datalen = val.DataLength & 0x7FFFFFFF
        valdata = val.vm.read(val.get_member_offset('Data'), datalen)
    elif val.DataLength > 0x4000:
        # Value is a BIG_DATA block, stored in chunked format
        datalen = val.DataLength
        big_data = Object("_CM_BIG_DATA", val.Data, val.vm, profile=val.profile)
        valdata = ""
        for chunk in big_data.List:
            amount_to_read = min(BIG_DATA_MAGIC, datalen)
            chunk_data = val.vm.read(chunk, amount_to_read)
            if not chunk_data:
                valdata = None
                break
            valdata += chunk_data
            datalen -= amount_to_read
    else:
        datalen = val.DataLength
        valdata = val.vm.read(val.Data, datalen)

    if not valdata:
        default = _DEFAULTS.get(valtype, "")
        return (valtype,default)

    if (valtype == "REG_SZ" or valtype == "REG_EXPAND_SZ" or
        valtype == "REG_LINK"):
        try:
            valdata = valdata.decode('utf-16-le')
        except UnicodeDecodeError, e:
            try:
                valdata = valdata[:-1].decode('utf-16-le')
            except UnicodeDecodeError, e:
                valdata = ""
    elif valtype == "REG_MULTI_SZ":
        try:
            valdata = valdata.decode('utf-16-le').split('\0')
        except UnicodeDecodeError:
            valdata = []
    elif valtype == "REG_DWORD":
        if len(valdata) != 4:
            default = _DEFAULTS.get(valtype, "")
            return (valtype,default)
        valdata = unpack("<L", valdata)[0]
    elif valtype == "REG_DWORD_BIG_ENDIAN":
        if len(valdata) != 4:
            default = _DEFAULTS.get(valtype, "")
            return (valtype,default)
        valdata = unpack(">L", valdata)[0]
    elif valtype == "REG_QWORD":
        if len(valdata) != 8:
            default = _DEFAULTS.get(valtype, "")
            return (valtype,default)
        valdata = unpack("<Q", valdata)[0]
    return (valtype,valdata)

def value_string(val):
    """Return a safe string representation of the value data"""
    tp, data = value_data(val)
    if (tp == "REG_SZ" or tp == "REG_EXPAND_SZ" or
        tp == "REG_LINK"):
        data = data.encode('ascii', 'backslashreplace')
    elif (tp == "REG_DWORD" or tp == "REG_QWORD" or
          tp == "REG_DWORD_BIG_ENDIAN"):
        pass
    elif tp == "REG_MULTI_SZ":
        data = ",".join(d.encode('ascii', 'backslashreplace') for d in data)
    else: # binary data
        data = " ".join("%02x" % ord(c) for c in data)

    return tp, data

def value_raw_data(val):
    """Return the raw data of a value"""
    inline =  val.DataLength & 0x80000000

    if inline:
        valdata = val.vm.read(val.get_member_offset('Data'), val.DataLength & 0x7FFFFFFF)
    else:
        valdata = val.vm.read(val.Data, val.DataLength)

    return valdata

def walk(root):
    yield root
    for k in subkeys(root):
        for j in walk(k):
            yield j
