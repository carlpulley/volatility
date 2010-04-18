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
from forensics.win32.modules import *
from forensics.win32.executable import rebuild_exe_mem

import pefile
import pydasm

class driver:
    def __init__(self, name=None, base=None, size=None):
        self.name = name
        self.base = base
        self.size = size

def inside_module(start, size, addr):
    if (addr < start) or (addr > ((start+size) & 0xffffffff)):
        return False
    return True

def get_module_by_addr(drvlist, addr):
    for drv in drvlist:
        if (addr > drv.base) and (addr < ((drv.base+drv.size) & 0xffffffff)):
            return drv
    return None
    
def rebuild_pe(addr_space, types, pe_base, pe_filename):
    try:
        f = open(pe_filename, 'wb')
        rebuild_exe_mem(addr_space, types, pe_base, f, True)
        f.close()
    except:
        pass

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

class kernel_hooks(forensics.commands.command):

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

    def help(self):
        return  "Locate IAT/EAT/in-line API hooks in kernel space"

    def execute(self):
        
        self.processes = []

        op = self.op
        opts = self.opts

        if (opts.filename is None) or (not os.path.isfile(opts.filename)):
            op.error("File is required")
        else:
            filename = opts.filename
            
        if (opts.dir is None):
            op.error("Directory is required")
        else:
            if not os.path.isdir(opts.dir):
                os.mkdir(opts.dir)
            moddir = opts.dir
            
        print ""

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
            
        for drv in drvlist:
                
            space = find_space(addr_space, types, symtab, drv.base)
            modfname = "%s/driver.%x.sys" % (moddir, drv.base)
            rebuild_pe(space, types, drv.base, modfname)

            if (not os.path.isfile(modfname)):
                print "[!] Error dumping driver at offset 0x%x" % drv.base
                continue

            if os.path.getsize(modfname) == 0:
                os.remove(modfname)
                print "[!] Error dumping driver at offset 0x%x" % drv.base
                continue

            data = open(modfname, 'rb').read()
            try:
                pe = pefile.PE(data=data)
            except:
                continue
                
            if (hasattr(pe, 'DIRECTORY_ENTRY_IMPORT')): 
                
                for imported_module in pe.DIRECTORY_ENTRY_IMPORT:
                    
                    thedriver = None
                    
                    for d in drvlist:
                        if imported_module.dll.lower() in d.name.lower():
                            thedriver = d
                            break
                            
                    if thedriver == None:
                        continue
                    
                    for symbol in imported_module.imports:
                        
                        if symbol.import_by_ordinal is True:
                            continue
                            
                        if symbol.bound:

                            if not inside_module(thedriver.base, thedriver.size, symbol.bound):
                                
                                d = get_module_by_addr(drvlist, symbol.bound)
                                hooking_driver = d.name if d is not None else ""
                                
                                print "Type: IAT, Hooked Driver: %s (0x%x - 0x%x), Hooked Function: %s:%s => 0x%x, Hooking driver: %s" % (drv.name, drv.base, (drv.base + drv.size), imported_module.dll, symbol.name, symbol.bound, hooking_driver)
            
            if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                continue
                                
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                
                if exp.name is None or exp.name == "":
                    exp.name = exp.ordinal
                    
                export_va  = (drv.base + exp.address) & 0xffffffff
                drv_end = (drv.base + drv.size) & 0xffffffff
                
                try:
                    if (export_va < drv.base) or (export_va > drv_end):
                    
                        d = get_module_by_addr(drvlist, export_va)
                        hooking_driver = d.name if d is not None else ""
                    
                        print "Type: EAT, Hooked driver: %s, Hooked function: %s => 0x%x, Hooking driver: %s" % (drv.name, exp.name, export_va, hooking_driver)
                        continue
                except:
                    continue
                
                hook_destination, instruction = check_inline(pe, exp.address, export_va)
                    
                if (hook_destination is not None) and (instruction is not None):
                    
                    if not inside_module(drv.base, drv.size, hook_destination):
                        
                        d = get_module_by_addr(drvlist, hook_destination)
                        hooking_driver = d.name if d is not None else ""
                        
                        print "Type: INLINE, Hooked driver: %s (0x%x - 0x%x), Hooked function: %s => %s, Hooking driver: %s" % (drv.name, drv.base, (drv.base + drv.size), exp.name, instruction, hooking_driver)
        print ""
