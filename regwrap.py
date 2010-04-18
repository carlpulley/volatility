"""
regrap.py

A thin wrapper around Volatility's registry API that exposes
a compatible interface to Perl's Parse::Win32Registry.

Along with Inline::Python, this lets programs that expect
hive files to run against memory images.
"""

import sys
from vtypes import xpsp2types as types
from forensics.win32.regtypes import regtypes
from forensics.win32.rawreg import *
from forensics.win32.hive2 import HiveAddressSpace
from forensics.win32.datetime import windows_to_unix_time
from forensics.object import read_obj
from forensics.object2 import Profile
from vutils import *
from vsyms import *

import forensics.registry as MemoryRegistry

# Loader stuff we have to do ourselves because vutils
# assumes we're using the stock command parser

class Op:
    def error(self,msg):
        print >> sys.stderr, msg
        sys.exit(1)

def load_image(filename):
    dtb = guess_dtb(filename, Op())
    addr_space = load_pae_address_space(filename, dtb)
    if addr_space:
        symtab = pae_syms   
    else:
        addr_space = load_nopae_address_space(filename, dtb)
        if addr_space:
            symtab = nopae_syms
    MemoryRegistry.Init()
    return (addr_space, symtab, types)

# Wrapper classes

class RegWrapper:
    # Note that "filename" also includes the hive vaddr
    def __init__(self, filename):
        fname,hive_addr = filename.rsplit('@',1)
        hive_addr = int(hive_addr,0)

        self.addr_space, self.symtab, self.types = load_image(fname)
        self.hive_vaddr = hive_addr
        self.hive = HiveAddressSpace(self.addr_space, self.types, self.hive_vaddr)

        types.update(regtypes)
        self.types.update(regtypes)
        self.profile = Profile()

        ts = read_obj(self.addr_space, self.types, ['_HBASE_BLOCK', 'TimeStamp', 'QuadPart'],
                      self.hive.baseblock)
        self.timestamp = windows_to_unix_time(ts)
        
    def get_root_key(self):
        return Key(get_root(self.hive, self.profile))

    def get_timestamp(self):
        return self.timestamp

    def get_timestamp_as_string(self):
        tuple_time = gmtime(self.timestamp)
        iso_time = time.strftime("%Y-%m-%dT%H:%M:%SZ", tuple_time)
        return iso_time

    def get_embedded_filename(self):
        return "[unimplemented]"
    
class Key:
    def __init__(self, volkey, parent_path=None):
        if not parent_path:
            self.path = volkey.Name
        else:
            self.path = parent_path + "\\" + volkey.Name

        self.volkey = volkey
        self.timestamp = windows_to_unix_time(self.volkey.LastWriteTime.QuadPart)
    
    def get_name(self):
        return self.volkey.Name

    def get_path(self):
        return self.path

    def get_subkey(self, keyname):
        keyname_l = keyname.split("\\")
        volsk = open_key(self.volkey, keyname_l)
        if not volsk: return None

        sub_path = "\\".join(keyname_l[:-1])
        if sub_path:
            path = self.path + "\\" + sub_path
        else:
            path = self.path
        
        return Key(volsk, parent_path=path)

    def get_value(self, valname):
        vals = values(self.volkey)
        v = None
        for val in vals:
            if val.Name.upper() == valname.upper():
                v = Value(val)
                break
        return v

    def get_list_of_subkeys(self):
        volsks = subkeys(self.volkey)
        return [Key(sk, parent_path=self.path) for sk in volsks]

    def get_list_of_values(self):
        return [Value(v) for v in values(self.volkey)]

    def get_timestamp(self):
        return self.timestamp

    def get_timestamp_as_string(self):
        tuple_time = gmtime(self.timestamp)
        iso_time = time.strftime("%Y-%m-%dT%H:%M:%SZ", tuple_time)
        return iso_time

    def as_string(self):
        return self.get_path() + " [%s]" % self.get_timestamp_as_string()

    def as_regedit_export(self):
        raise Exception("Unimplemented: as_regedit_export()")

    def print_summary(self):
        print self.as_string()

    def get_parent(self):
        raise Exception("Unimplemented: get_parent()")

    def is_root(self):
        return self.volkey.offset == 0x20

class Value:
    def __init__(self, volval):
        self.volval = volval
        self.type, self.data = value_data(self.volval)
        if self.type == "REG_SZ" or self.type == "REG_EXPAND_SZ":
            self.data = self.data.split('\x00')[0]
        self.num_type = self.volval.Type

    def get_name(self):
        return self.volval.Name

    def get_type(self):
        return self.num_type

    def get_type_as_string(self):
        return self.type

    def get_data(self):
        return self.data

    def get_data_as_string(self):
        if self.type == "REG_SZ" or self.type == "REG_EXPAND_SZ":
            data_str = self.data
        elif self.type == "REG_MULTI_SZ":
            data_str = " ".join( "[%d] %s" % (i, s) for i, s in enumerate(self.data) )
        elif self.type == "REG_DWORD":
            data_str = "%#08x (%d)" % (self.data, self.data)
        else:
            data_str = " ".join("%02x" % ord(c) for c in self.data)
        return data_str

    def get_raw_data(self):
        inline = self.volval.DataLength & 0x80000000
        if inline:
            valdata = self.volval.vm.read(self.volval.get_member_offset('Data'),
                                          self.volval.DataLength & 0x7FFFFFFF)
        else:
            valdata = self.volval.vm.read(self.volval.Data, self.volval.DataLength)
        return valdata
        
    def as_string(self):
        name = self.get_name()
        if not name: name = "(Default)"
        return "%s (%s) = %s" % (name, self.type, self.get_data_as_string())

    def as_regedit_export(self):
        raise Exception("Unimplemented: as_regedit_export()")

    def print_summary(self):
        print self.as_string()
