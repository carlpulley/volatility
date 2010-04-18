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
from forensics.object2 import *
from forensics.win32.modules import *
from forensics.win32.executable import rebuild_exe_mem

from operator import itemgetter
from bisect import bisect_right

import pefile
import shutil
import pydasm
import time

use_filter = True

def module_name(process_address_space, types, module_vaddr):
    return read_unicode_string(process_address_space, types,
                    ['_LDR_DATA_TABLE_ENTRY', 'BaseDllName'], module_vaddr)    
        
class module:
    def __init__(self, name=None, path=None, base=None, size=None):
        self.name = name
        self.path = path
        self.base = base
        self.size = size
        
def get_module_by_name(all_modules, name):
    for mod in all_modules:
        if name.lower() == mod.name.lower():
            return mod
    return None
    
def get_module_by_addr(all_modules, addr):
    for mod in all_modules:
        if (addr >= mod.base and 
            addr <  mod.base + mod.size):
            return mod
    return None
    
def rebuild_pe(addr_space, types, pe_base, pe_filename):

    pe = None

    try:
        f = open(pe_filename, 'wb')
        rebuild_exe_mem(addr_space, types, pe_base, f, True)
        f.close()
        
        pe = pefile.PE(pe_filename, fast_load=True)
        pe.parse_data_directories( directories=[ 
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS'] ] )
    except:
        pass

    return pe

def find_space(addr_space, types, symtab, addr):
    # short circuit if given one works
    if addr_space.is_valid_address(addr): return addr_space

    pslist = process_list(addr_space, types, symtab)
    for p in pslist:
        dtb = process_dtb(addr_space, types, p)
        space = create_addr_space(addr_space, dtb)
        if space.is_valid_address(addr):
            return space
    return None
    
def check_inline(pe, export_rva, export_va):
    try:
        bytes = pe.get_data(export_rva, 24)
    except:
        print "[!] Cannot read RVA at 0x%x" % export_rva
        return None, None

    i1 = pydasm.get_instruction(bytes, pydasm.MODE_32)
    if not i1:
        return None, None

    i2 = pydasm.get_instruction(bytes[i1.length:], pydasm.MODE_32)
    if not i2:
        return None, None

    hook_destination = None
    instruction = None

    if (i1.type == pydasm.INSTRUCTION_TYPE_JMP):

        if (i1.op1.type == pydasm.OPERAND_TYPE_MEMORY):

            hook_destination = (i1.op1.displacement & 0xffffffff)
            instruction = "jmp [0x%x]" % hook_destination

        elif (i1.op1.type == pydasm.OPERAND_TYPE_IMMEDIATE):

            hook_destination = export_va + i1.op1.immediate + i1.length
            instruction = "jmp 0x%x" % hook_destination

    elif (i1.type == pydasm.INSTRUCTION_TYPE_CALL):

        if (i1.op1.type == pydasm.OPERAND_TYPE_MEMORY):

            hook_destination = (i1.op1.displacement & 0xffffffff)
            instruction = "call [0x%x]" % hook_destination

        elif (i1.op1.type == pydasm.OPERAND_TYPE_IMMEDIATE):

            hook_destination = export_va + i1.op1.immediate + i1.length
            instruction = "call 0x%x" % hook_destination

    elif (i1.type == pydasm.INSTRUCTION_TYPE_PUSH) and (i2.type == pydasm.INSTRUCTION_TYPE_RET):

        hook_destination = i1.op1.immediate
        instruction = "push dword 0x%x; ret" % hook_destination

    return hook_destination, instruction

class apihooks(forensics.commands.command):

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
        
        self.op.add_option('-d', '--dir',
            help='Output directory for dumped modules',
            action='store', type='string', dest='dir')
            
        self.op.add_option('-k', '--kernel',
            help='Scan kernel modules',
            action='store_true',dest='kscan', default=False)
            
        self.op.add_option('-p', '--pid',
            help='Only scan process with specified pid',
            action='store',dest='pid', type='int')

    def help(self):
        return  "[VAP] Detect API hooks in user and/or kernel space"
        
    def user_scan(self):
    
        op = self.op
        opts = self.opts
        
        t0 = time.time()
        
        (addr_space, symtab, types) = load_and_identify_image(op, opts)
        all_tasks = process_list(addr_space, types, symtab)
       
        for task in all_tasks:
        
            if not addr_space.is_valid_address(task):
                continue
                
            process_id = process_pid(addr_space, types, task)
                
            if (opts.pid != None) and (process_id != opts.pid):
                continue
                
            image_file_name = process_imagename(addr_space, types, task)
            
            if image_file_name == None:
                image_file_name = "UNKNOWN"
            
            process_address_space = process_addr_space(addr_space, types, task, opts.filename)
            
            if process_address_space == None:
                continue
                
            peb = process_peb(addr_space, types, task)
            
            if not process_address_space.is_valid_address(peb):
                continue
                
            mods = process_ldrs(process_address_space, types, peb)
            all_modules = []
            
            for mod in mods:
            
                if not process_address_space.is_valid_address(mod):
                    continue
                    
                mod_path = module_path(process_address_space, types, mod)
                mod_name = module_name(process_address_space, types, mod)
                mod_base = module_base(process_address_space, types, mod)
                mod_size = module_size(process_address_space, types, mod)
                
                if  (mod_path == None) or \
                    (mod_name == None) or \
                    (mod_base == None) or \
                    (mod_size == None):
                    continue
                    
                all_modules.append(module(mod_name, mod_path, mod_base, mod_size))
                
            for mod in all_modules:
            
                if process_address_space.vtop(mod.base) == None:
                    continue
                    
                rebuilt_name = "%s/%s.%d.%x.%s" % (
                                opts.dir, image_file_name, process_id, mod.base, mod.name)
                
                pe = rebuild_pe(process_address_space, types, mod.base, rebuilt_name)
                if pe == None:
                    print "Cannot parse PE at 0x%x (%s) for pid 0x%x (%s)" % (
                                mod.base, 
                                mod.name,
                                process_id,
                                image_file_name
                                )
                    continue
                    
                # misc feature to alert on any PE files with TLS entries
                if (hasattr(pe, 'DIRECTORY_ENTRY_TLS') and \
                        pe.DIRECTORY_ENTRY_TLS and \
                        pe.DIRECTORY_ENTRY_TLS.struct):
                        
                    print "TLS directory present in %s, check for anti-debugging" % rebuilt_name

                # start the IAT hook detection by making sure the IAT is accessible 
                if (hasattr(pe, 'DIRECTORY_ENTRY_IMPORT')): 
                    
                    # loop once for each of the imported DLLs
                    for imp_mod in pe.DIRECTORY_ENTRY_IMPORT:
            
                        # get a list of the DLLs in the process space that match the name of the imported DLL. 
                        # this is important, for example, because a process might load comctl32.dll from both
                        # the system32 directory and the WinSxS directory for app compatibility  
                        
                        matching_modules = []
                        
                        for m in all_modules:
                            if m.name.lower() in imp_mod.dll.lower():
                                matching_modules.append(m)
                                
                        if len(matching_modules) == 0:
                            #print "Cannot find matching modules for %s in %s" % (imp_mod.dll, image_file_name)
                            continue
                            
                        # loop once for each of the imported functions in the DLL
                        for symbol in imp_mod.imports:
                            if symbol.import_by_ordinal is True:
                                continue
                                
                            if symbol.bound:
                                
                                # check to see if the imported function address points within one of the DLLs with a matching name
                                hook_mod = get_module_by_addr(all_modules, symbol.bound)
                                
                                if hook_mod not in matching_modules:
                                
                                    if hook_mod:
                                        hooking_module = hook_mod.path
                                    else:
                                        hooking_module = "UNKNOWN"
                                    
                                    if not use_filter or (use_filter and \
                                        # Ignore hooks that point inside C runtime libraries 
                                        ("msvcr" not in hooking_module.lower()) and ("msvcp" not in hooking_module.lower()) and \
                                        # Ignore hooks of WMI* that point inside Advapi32.dll
                                        (("wmi.dll" != imp_mod.dll.lower()) and ("advapi32.dll" not in hooking_module.lower())) and \
                                        # Ignore hooks of SCHANNEL* that point inside secur32.dll
                                        (("schannel.dll" != imp_mod.dll.lower()) and ("secur32.dll" not in hooking_module.lower())) and \
                                        # Ignore hooks that point inside ntdll.dll
                                        ("ntdll.dll" not in hooking_module.lower()) and \
                                        # Ignore hooks that point inside the Shim Engine - see http://www.alex-ionescu.com/?p=39
                                        ("shimeng.dll" not in hooking_module.lower())):
                                        
                                        self.CountUserIAT += 1
                                        
                                        print "%-8s %-16s %-6s %-40s %s!%-40s [0x%x] => 0x%-16x %-16s" % (
                                                "IAT", 
                                                image_file_name, 
                                                process_id, 
                                                mod.name, 
                                                imp_mod.dll, 
                                                symbol.name, 
                                                symbol.address, 
                                                symbol.bound, 
                                                hooking_module
                                                )
                                                
                # start the EAT and inline hook detection by making sure the EAT is accessible. 
                if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                    continue
                 
                # loop once for each exported function
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                
                    # use the export ordinal if the name isn't available
                    if exp.name is None or exp.name == "":
                        exp.name = exp.ordinal
                        
                    export_va  = (mod.base + exp.address) & 0xffffffff
                    hook_mod = get_module_by_addr(all_modules, export_va)
                    
                    if (hook_mod != mod):
                    
                        if hook_mod:
                            hooking_module = hook_mod.path
                        else:
                            hooking_module = "UNKNOWN"
                            
                        self.CountUserEAT += 1
                            
                        print "Type: EAT, Hooked driver: %s, Hooked function: %s => 0x%x, Hooking driver: %s" % (
                                        mod.name, 
                                        exp.name, 
                                        export_va, 
                                        hooking_module
                                        )
                                        
                        continue
                    
                    hook_destination, instruction = check_inline(pe, exp.address, export_va)
                    
                    if (hook_destination != None) and (instruction != None):

                        hook_mod = get_module_by_addr(all_modules, hook_destination)
                    
                        if hook_mod != mod:
                        
                            if hook_mod:
                                hooking_module = hook_mod.path
                            else:
                                hooking_module = "UNKNOWN"
                            
                            if not use_filter or (use_filter and \
                                # Ignore hooks of hooks in Microsoft C runtime libraries - almost all are hooked by default
                                not mod.name.lower().startswith('msvcp') and \
                                not mod.name.lower().startswith('msvcr')):
                                
                                self.CountUserINLINE += 1
                                
                                print "%-8s %-16s %-6s %-40s %-40s 0x%x => %-16s %-16s" % (
                                            "INLINE", 
                                            image_file_name,
                                            process_id, 
                                            mod.name, 
                                            exp.name, 
                                            export_va,
                                            instruction, 
                                            hooking_module
                                            )
        
    def kernel_scan(self):
        
        op = self.op
        opts = self.opts
        
        (addr_space, symtab, types) = load_and_identify_image(op, opts)        
        mods = modules_list(addr_space, types, symtab)
        all_modules = []
        
        for mod in mods:
            
            mod_name = module_modulename(addr_space, types, mod)
            mod_path = module_imagename(addr_space, types, mod)
            mod_base = module_baseaddr(addr_space, types, mod)
            mod_size = module_imagesize(addr_space, types, mod)
            
            if  (mod_name == None) or \
                (mod_path == None) or \
                (mod_base == None) or \
                (mod_size == None):
                continue
                
            all_modules.append(module(mod_name, mod_path, mod_base, mod_size))
        
        for mod in all_modules:
        
            space = find_space(addr_space, types, symtab, mod.base)
            modfname = "%s/driver.%x.sys" % (opts.dir, mod.base)
            
            pe = rebuild_pe(space, types, mod.base, modfname)
            if pe == None:
                print "Cannot dump or parse the PE at 0x%x" % mod.base
                continue
                
            if (hasattr(pe, 'DIRECTORY_ENTRY_IMPORT')): 
                
                for imported_module in pe.DIRECTORY_ENTRY_IMPORT:
                           
                    real_mod = get_module_by_name(all_modules, imported_module.dll)
                                    
                    if real_mod == None:
                        print "Cannot find module named %s" % imported_module.dll
                        continue
                    
                    for symbol in imported_module.imports:
                        
                        if symbol.import_by_ordinal is True:
                            continue
                            
                        if symbol.bound:
                            
                            hook_mod = get_module_by_addr(all_modules, symbol.bound)
                            
                            if hook_mod != real_mod:
                                
                                if hook_mod:
                                    hooking_driver = hook_mod.path
                                else:
                                    hooking_driver = "UNKNOWN"
                                    
                                self.CountKernelIAT += 1
                                
                                print "%-8s %-16s %-6s %-40s %s:%s => 0x%x %-16s" % (
                                                'IAT',
                                                '',
                                                '',
                                                mod.name, 
                                                imported_module.dll, 
                                                symbol.name, 
                                                symbol.bound, 
                                                hooking_driver
                                                )
            
            if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                continue
                                
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                
                if exp.name == None or exp.name == "":
                    exp.name = exp.ordinal
                    
                export_va  = (mod.base+ exp.address) & 0xffffffff
                
                hook_mod = get_module_by_addr(all_modules, export_va)
                    
                if (mod != hook_mod):
                
                    if hook_mod:
                        hooking_driver = hook_mod.path
                    else:
                        hooking_driver = "UNKNOWN"
                        
                    self.CountKernelEAT += 1
                        
                    print "%-8s %-16s %-6s %-40s %-40s %s => %-16s %-16s" % (
                                    'EAT',
                                    '',
                                    '',
                                    mod.name, 
                                    exp.name, 
                                    '',
                                    export_va, 
                                    hooking_driver
                                    )
                    continue
                    
                hook_destination, instruction = check_inline(pe, exp.address, export_va)
                    
                if (hook_destination != None) and (instruction != None):
                        
                    hook_mod = get_module_by_addr(all_modules, hook_destination)
                    
                    if hook_mod != mod:
                            
                        if hook_mod:
                            hooking_driver = hook_mod.path
                        else:
                            hooking_driver = "UNKNOWN"
                            
                        self.CountKernelINLINE += 1
                        
                        print "%-8s %-16s %-6s %-40s %-40s 0x%x => %-16s %-16s" % (
                                    'INLINE',
                                    '', 
                                    '',
                                    mod.name,
                                    exp.name,
                                    hook_destination,
                                    instruction, 
                                    hooking_driver
                                    )
        print ""

    def execute(self):
    
        self.CountKernelIAT = 0
        self.CountKernelEAT = 0
        self.CountKernelINLINE = 0
        
        self.CountUserIAT = 0
        self.CountUserEAT = 0
        self.CountUserINLINE = 0
        
        op = self.op
        opts = self.opts

        if (opts.filename is None) or (not os.path.isfile(opts.filename)):
            op.error("File is required")
        elif (opts.dir is None):
            op.error("Output directory is required")
        else:
            if not os.path.isdir(opts.dir):
                os.mkdir(opts.dir)
                if not os.path.isdir(opts.dir):
                    op.error("Cannot create output directory")
           
        t0 = time.time()
           
        print "\n%-8s %-16s %-6s %-40s %-40s %s => %-16s %-16s" % ("Type", "Process", "PID", "Hooked Module", "Hooked Function", "From", "To/Instruction", "Hooking Module")
           
        if opts.kscan:
            self.kernel_scan()
        else:
            self.user_scan()
        
        # delete all the dumped exe and dll files. comment this out to keep them for later analysis
        shutil.rmtree(opts.dir)
        
        print "Total IAT hooks in user space: %d" % self.CountUserIAT
        print "Total EAT hooks in user space: %d" % self.CountUserEAT
        print "Total INLINE hooks in user space: %d" % self.CountUserINLINE
        print "Total IAT hooks in kernel space: %d" % self.CountKernelIAT
        print "Total EAT hooks in kernel space: %d" % self.CountKernelEAT
        print "Total INLINE hooks in kernel space: %d" % self.CountKernelINLINE
        
        print "Completed after", time.time() - t0, " seconds!"