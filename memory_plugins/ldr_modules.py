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
from forensics.win32.tasks import *
from vtypes import xpsp2types
from forensics.win32.vad import *

LoadOrder   = 0
MemoryOrder = 1
InitOrder   = 2

module_orders = {LoadOrder   : 'InLoadOrderModuleList',
                 MemoryOrder : 'InMemoryOrderModuleList',
                 InitOrder   : 'InInitializationOrderModuleList'}
          
def get_mapped_modules(addr_space, types, task):

    mapped_files = {}

    VadRoot = process_vadroot(addr_space, types, task)
    if VadRoot == None or not addr_space.is_valid_address(VadRoot):
        return mapped_files

    vadlist = []
    traverse_vad(None, addr_space, types, VadRoot, append_entry, None, None, 0, vadlist)
    
    for vad_entry in vadlist: 
        tag_addr = vad_entry - 0x4
        if not addr_space.is_valid_address(tag_addr):
            continue

        tag = addr_space.read(tag_addr,4)
        StartingVpn = read_obj(addr_space, types, ['_MMVAD_LONG', 'StartingVpn'], vad_entry)
        StartingVpn = StartingVpn << 12
        
        ControlArea = read_obj(addr_space, types, ['_MMVAD_LONG', 'ControlArea'], vad_entry)
        if not addr_space.is_valid_address(ControlArea): 
            continue
            
        ControlAreaObject = addr_space.read(ControlArea,obj_size(types,'_CONTROL_AREA'))
        if not addr_space.is_valid_address(ControlArea) or ControlAreaObject == None:
            return None
            
        FilePointer = controlarea_filepointer(addr_space, types, ControlArea)
        if FilePointer != None and addr_space.is_valid_address(FilePointer) and FilePointer != 0x0:
            data = get_first_page(addr_space, StartingVpn)
            if data != None:
                if data[0:2] == 'MZ':
                    mapped_files[StartingVpn] = file_name(addr_space, types, FilePointer)
            
    return mapped_files
    
def get_first_page(process_address_space, StartingVpn):
    range_data = '' 

    if (StartingVpn == 0) or (StartingVpn > 0x7FFFFFFF-0x1000):
        return None

    if not process_address_space.is_valid_address(StartingVpn):
        return None

    return process_address_space.read(StartingVpn, 0x1000)

def print_ldr_modules(process_address_space, types, mapped_files, modules, offset):

    i = 1
       
    print "%-6s %-8s %-12s %-12s %-12s %s" % ('No.', 'Map?', 'Offset', 'Base', 'Size', 'Path')
    
    for module in modules:
    
        if not process_address_space.is_valid_address(module):
            continue
            
        path = read_unicode_string(process_address_space, types,
                ['_LDR_DATA_TABLE_ENTRY', 'FullDllName'], module-offset)   
        if path is None:
            path = ""
        
        base = read_obj(process_address_space, types,
                ['_LDR_DATA_TABLE_ENTRY', 'DllBase'], module-offset)
        if base is None:
            base = 0
        
        size = read_obj(process_address_space, types,
                ['_LDR_DATA_TABLE_ENTRY', 'SizeOfImage'], module-offset)
        if size is None:
            size = 0
        
        if mapped_files.has_key(base):
            hint = '[x]'
        else:
            hint = '[ ]'
            
        print "[%-4d] %-8s 0x%-12x 0x%-12x 0x%-12x %s" % (i, hint, module, base, size, path)   
        
        i+=1
    
    print

def listed(process_address_space, types, modules, offset, base, name):
    present = False
    
    for module in modules:
        
        if not process_address_space.is_valid_address(module):
            continue
            
        mod_name = read_unicode_string(process_address_space, types,
                ['_LDR_DATA_TABLE_ENTRY', 'FullDllName'], module-offset)   
        if mod_name is None:
            continue
        
        mod_base = read_obj(process_address_space, types,
                ['_LDR_DATA_TABLE_ENTRY', 'DllBase'], module-offset)
        if mod_base is None:
            continue
            
        if (mod_base == base) and (name.lower() in mod_name.lower()):
            return True
            
    return present

def process_ldrs_ex(process_address_space, types, peb_vaddr, order):
    ldr = read_obj(process_address_space, types,
                   ['_PEB', 'Ldr'], peb_vaddr)

    module_list = []

    if ldr is None:
        #print "Unable to read ldr for peb 0x%x" % (peb_vaddr)
        return module_list
        
    if not module_orders.has_key(order):
        #print "Invalid list order"
        return module_list
        
    first_module = read_obj(process_address_space, types,
                            ['_PEB_LDR_DATA', module_orders[order], 'Flink'],
                            ldr)

    if first_module is None:
        return module_list     
    
    this_module = first_module

    next_module = read_obj(process_address_space, types,
                         ['_LDR_DATA_TABLE_ENTRY', 'InLoadOrderLinks', 'Flink'],
                           this_module)

    if next_module is None:
        #print "ModuleList Truncated, unable to read module at 0x%x\n" % (this_module)        
        return module_list
    
    while next_module != first_module:
        module_list.append(this_module)
        if not process_address_space.is_valid_address(next_module):
            #print "ModuleList Truncated, unable to read module at 0x%x\n" % (next_module)
            return module_list
        prev_module = this_module
        this_module = next_module
        next_module = read_obj(process_address_space, types,
                         ['_LDR_DATA_TABLE_ENTRY', 'InLoadOrderLinks', 'Flink'],
                         this_module)

        
    return module_list

class ldr_modules(forensics.commands.command):

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
            help='Examine this pid only',
            action='store', type='int', dest='pid')
            
        self.op.add_option('-v', '--verbose',
            help='Verbose output (show entries from the 3 LDR_MODULE lists)',
		    action='store_true',dest='verbose', default=False)

    def help(self):
        return "[VAP] Detect unlinked LDR_MODULE using mapped file names"

    def execute(self):

        op = self.op
        opts = self.opts

        if (opts.filename is None) or (not os.path.isfile(opts.filename)):
            op.error("File is required")
        else:
            filename = opts.filename
        
        xpsp2types['_PEB_LDR_DATA'][1]['InMemoryOrderModuleList'] = [ 0x14, ['_LIST_ENTRY']]
        xpsp2types['_PEB_LDR_DATA'][1]['InInitializationOrderModuleList'] = [ 0x1c, ['_LIST_ENTRY']]
        
        xpsp2types['_LDR_MODULE'][1]['InMemoryOrderModuleList'] = [ 0x8, ['_LIST_ENTRY']]
        xpsp2types['_LDR_MODULE'][1]['InInitializationOrderModuleList'] = [ 0x10, ['_LIST_ENTRY']]

        (addr_space, symtab, types) = load_and_identify_image(op, opts)
        
        all_tasks = process_list(addr_space, types, symtab)        

        if not opts.pid == None:
            all_tasks = process_find_pid(addr_space,types, symtab, all_tasks, opts.pid)
            if len(all_tasks) == 0:
                print "Error process [%d] not found" % opts.pid
        
        print "%-8s %-20s %-12s %-8s %-8s %-8s %-8s" % ('Pid', 'Name', 'PEB', 'nLoad', 'nMem', 'nInit', 'nMapped')
    
        for task in all_tasks:

            if not addr_space.is_valid_address(task):
                continue
        
            image_file_name = process_imagename(addr_space, types, task)

            process_id = process_pid(addr_space, types, task)
        
            process_address_space = process_addr_space(addr_space, types, task, opts.filename)
            if process_address_space is None:
                continue
                            
            mapped_files = get_mapped_modules(process_address_space, types, task)
            
            peb = process_peb(addr_space, types, task)

            if not process_address_space.is_valid_address(peb):
                continue
                
            inloadorder   = process_ldrs_ex(process_address_space, types, peb, LoadOrder) 
            inmemoryorder = process_ldrs_ex(process_address_space, types, peb, MemoryOrder)
            ininitorder   = process_ldrs_ex(process_address_space, types, peb, InitOrder)
    
            print "%-8x %-20s 0x%-12x %-8d %-8d %-8d %-8s" % (
                                                process_id, 
                                                image_file_name, 
                                                peb, len(inloadorder), 
                                                len(inmemoryorder), 
                                                len(ininitorder), 
                                                len(mapped_files)
                                                )

            if opts.verbose:
                print
                print module_orders[LoadOrder]
                print_ldr_modules(process_address_space, types, mapped_files, inloadorder, 0)
                print module_orders[MemoryOrder]
                print_ldr_modules(process_address_space, types, mapped_files, inmemoryorder, 0x8)
                print module_orders[InitOrder]
                print_ldr_modules(process_address_space, types, mapped_files, ininitorder, 0x10)
                
                print "Mapped Files"
                print "%-6s %-6s %-6s %-6s 0x%-12s %-8s" % ('No.', 'Load?', 'Mem?', 'Init?', 'Base', 'Name')
                i = 1
                for base,name in mapped_files.iteritems():
                    print "[%4d] %-6s %-6s %-6s 0x%-12x %s" % ( 
                        i, 
                        "[x]" if listed(process_address_space, types, inloadorder, 0, base, name) else "[ ]", 
                        "[x]" if listed(process_address_space, types, inmemoryorder, 0x8, base, name) else "[ ]", 
                        "[x]" if listed(process_address_space, types, ininitorder, 0x10, base, name) else "[ ]", 
                        base, 
                        name
                        )
                    i+=1 
                print 