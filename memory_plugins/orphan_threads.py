# Volatility
# Copyright (C) 2008 Volatile Systems
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

from vutils import *
from forensics.win32.modules import *
from forensics.object2 import *
from forensics.win32.scan2 import *

class driver:
    def __init__(self, name=None, base=None, size=None):
        self.name = name
        self.base = base
        self.size = size
        
class threads:
    def __init__(self, pid=None, tid=None, startaddr=None, offset=None):
        self.pid = pid
        self.tid = tid
        self.startaddr = startaddr
        self.offset = offset
        
def has_module(drvlist, startaddr):
    for drv in drvlist:
        if ( (startaddr > drv.base) and (startaddr < drv.base+drv.size) ):
            return True
    return False
        
class PoolScanThreadFast3(PoolScanThreadFast2):
    def __init__(self, addr_space, thread_list):
        GenMemScanObject.__init__(self, addr_space)
        self.pool_tag = "\x54\x68\x72\xE5"
        self.pool_size = 0x278
        self.thread_list = thread_list

    class Scan(PoolScanThreadFast2.Scan):
        def object_action(self, buff, object_offset):
            UniqueProcess =  read_obj_from_buf(buff, self.data_types, \
                ['_ETHREAD', 'Cid', 'UniqueProcess'], object_offset)

            UniqueThread =  read_obj_from_buf(buff, self.data_types, \
                ['_ETHREAD', 'Cid', 'UniqueThread'], object_offset)                     
            StartAddress = read_obj_from_buf(buff, self.data_types, \
	                    ['_ETHREAD', 'StartAddress'], object_offset)            
            address = self.as_offset + object_offset
            
            thrd = threads(UniqueProcess, UniqueThread, StartAddress, address)
            self.outer.thread_list.append(thrd)
        
class orphan_threads(forensics.commands.command):

    # Declare meta information associated with this plugin

    meta_info = forensics.commands.command.meta_info
    meta_info['author'] = 'Michael Ligh'
    meta_info['copyright'] = 'Copyright (c) 2008,2009 Michael Ligh'
    meta_info['contact'] = 'michael.ligh@mnin.org'
    meta_info['license'] = 'GNU General Public License 2.0 or later'
    meta_info['url'] = 'http://www.mnin.org'
    meta_info['os'] = 'WIN_32_XP_SP2'
    meta_info['version'] = '1.0'

    def parser(self):
        forensics.commands.command.parser(self)

        self.op.add_option('-p', '--pid',
            help='Identify the system process id (default is 4)',
            action='store', type='int', dest='pid', default=4)

    def help(self):
        return  "Find kernel threads that don't map back to loaded modules"

    def execute(self):

        op = self.op
        opts = self.opts

        if (opts.filename is None) or (not os.path.isfile(opts.filename)) :
            op.error("File is required")
        else:
            filename = opts.filename
            
        (addr_space, symtab, types) = load_and_identify_image(op, opts)        
        all_modules = modules_list(addr_space, types, symtab)
        drvlist = []

        for module in all_modules:
            if not addr_space.is_valid_address(module):
                continue

            mod_name = module_modulename(addr_space, types, module)
            if mod_name is None:
                mod_name = ""

            mod_base = module_baseaddr(addr_space, types, module)
            if mod_base is None:
                mod_base = ""

            mod_size = module_imagesize(addr_space, types, module)
            if mod_size is None:
                mod_size = 0

            drv = driver(mod_name, mod_base, mod_size)
            drvlist.append(drv)
            
        try:
            flat_address_space = FileAddressSpace(opts.filename,fast=True)
        except:
            print "[!] Error: Cannot open %s for reading\n" % opts.filename
            return

        meta_info.set_datatypes(types)
        search_address_space = find_addr_space(flat_address_space, types)
        sysdtb = get_dtb(search_address_space, types) 
        meta_info.set_dtb(sysdtb)

        kaddr_space = load_pae_address_space(opts.filename, sysdtb)
        if kaddr_space is None:
            kaddr_space = load_nopae_address_space(opts.filename, sysdtb)
        meta_info.set_kas(kaddr_space)

        scanners = []
        threads_list = []
        
        scanners.append((PoolScanThreadFast3(search_address_space, threads_list)))
        scan_addr_space(search_address_space,scanners)
        
        print ""
        print "PID    TID    Offset    StartAddress\n"+ \
              "------ ------ --------- ------------";
            
        for t in threads_list:
            if (t.pid == opts.pid) and (not has_module(drvlist, t.startaddr)):
                print "%6s %6s 0x%x 0x%x" % (t.pid, t.tid, t.offset, t.startaddr)
                
        print ""
        
        

        
        