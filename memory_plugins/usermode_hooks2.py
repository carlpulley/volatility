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
from forensics.win32.executable import rebuild_exe_mem

from string import atoi
import commands
import shutil
import pefile
import pydasm

use_filter = True

class dll:
    def __init__(self, dll_full_path=None, base=None, size=None):
        self.dll_full_path = dll_full_path
        self.base = base
        self.size = size

class process:
    def __init__(self, pid=None, exe_name=None):
        self.pid = pid
        self.exe_name = exe_name
        self.modules = []

def inside_module(start, size, addr):
    if (addr < start) or (addr > start+size):
        return False
    return True

def get_module_by_addr(p, addr):
    for m in p.modules:
        if (addr > m.base) and (addr < m.base+m.size):
            return m
    return None
    
def get_modlist(p, module_to_find):
    modlist = []
    for m in p.modules:
        if module_to_find in m.dll_full_path.lower().split('\\')[-1]:
            modlist.append(m)
    return modlist

class usermode_hooks(forensics.commands.command):

    # Declare meta information associated with this plugin

    meta_info = forensics.commands.command.meta_info
    meta_info['author'] = 'MHL @ iDEFENSE'
    meta_info['copyright'] = 'Copyright (c) 2008,2009 Michael Ligh'
    meta_info['contact'] = 'michael.ligh@mnin.org'
    meta_info['license'] = 'GNU General Public License 2.0 or later'
    meta_info['url'] = 'http://www.mnin.org'
    meta_info['os'] = 'WIN_32_XP_SP2'
    meta_info['version'] = '1.0'

    def parser(self):

        forensics.commands.command.parser(self)

        self.op.add_option('-d', '--dir',
            help='Output directory for dumped dll and exe files',
            action='store', type='string', dest='dir')

        self.op.add_option('-p', '--pid',
            help='Find hooks in this process only',
            action='store', type='string', dest='pid')

    def help(self):
        return  "Locate IAT/EAT/in-line API hooks in user space"

    def execute(self):
        
        self.processes = []

        op = self.op
        opts = self.opts

        if (opts.filename is None) or (not os.path.isfile(opts.filename)):
            op.error("File is required")
        else:
            filename = opts.filename

        if (opts.dir is None):
            op.error("Output directory is required")
        else:
            outdir = opts.dir 
            if not os.path.isdir(outdir):
                os.mkdir(outdir)
            if not os.path.isdir(outdir):
                op.error("Cannot create output directory")

        print "\n%-8s %-16s %-6s %-40s %-40s %s => %-16s %-16s" % ("Type", "Process", "PID", "Hooked Module", "Hooked Function", "From", "To/Instruction", "Hooking Module")

        # basic process listing code from pslist
        (addr_space, symtab, types) = load_and_identify_image(op, opts)
        all_tasks = process_list(addr_space, types, symtab)

        # get list of windows processes
        all_tasks = process_list(addr_space, types, symtab)        

        star_line = '*'*72
    
        for task in all_tasks:

            if not addr_space.is_valid_address(task):
                continue
        
            image_file_name = process_imagename(addr_space, types, task)
            process_id = process_pid(addr_space, types, task)
            
            if image_file_name == None:
                image_file_name = "UNKNOWN"

            if (opts.pid is not None) and (int(opts.pid) != process_id):
                continue
        
            process_address_space = process_addr_space(addr_space, types, task, opts.filename)
            if process_address_space is None:
                print "Error obtaining address space for process [%d]" % (process_id)
                continue
                            
            peb = process_peb(addr_space, types, task)

            if not process_address_space.is_valid_address(peb):
                print "Error obtaining PEB for process [%d]" % (process_id)
                continue
            
            # get the image base of the process
            img_base = read_obj(process_address_space, types, ['_PEB', 'ImageBaseAddress'], peb)

            if img_base == None:
                print "Error: Image base not memory resident for process [%d]" % (process_id)
                continue

            if process_address_space.vtop(img_base) == None:
                print "Error: Image base not memory resident for process [%d]" % (process_id)
                continue
        
            # save the process in the process list
            p = process(process_id, image_file_name)
            self.processes.append(p)
    
            modules = process_ldrs(process_address_space, types, peb)
        
            # loop once to build the module list for the exe with base address and sizes
            for module in modules:
                
                if not process_address_space.is_valid_address(module):
                    continue
                    
                path = module_path(process_address_space, types, module)
                base = module_base(process_address_space, types, module)
                size = module_size(process_address_space, types, module)
                
                if (path is None) or (base is None) or (size is None):
                    continue
                    
                # save the dll in the process' dll list
                m = dll(path, base, size)
                p.modules.append(m)
                
            # loop again to process each module's IAT and EAT
            for module in modules:
                
                if not process_address_space.is_valid_address(module):
                    continue
                    
                path = module_path(process_address_space, types, module)
                base = module_base(process_address_space, types, module)
                size = module_size(process_address_space, types, module)
                
                if (path is None) or (base is None) or (size is None):
                    continue
                
                if process_address_space.vtop(base) == None:
                    continue

                # this dumps exe and dlls since exes are essentially modules in the process space
                # just like in malfind, use with caution to avoid directory traversal attacks
                rebuilt_name = "%s/%s.%d.%x.%s" % (outdir, image_file_name, process_id, base, path.split('\\')[-1])
                of = open(rebuilt_name, 'wb')
                try:
                    rebuild_exe_mem(process_address_space, types, base, of, True)
                except:
                    print "Error: Unable to dump executable from base address 0x%x in process %d" % (base, process_id)
                    continue
                finally:
                    of.close()
                
                data = open(rebuilt_name, 'rb').read()
                if data[0:2] == 'MZ':
                    # use this in try/except block in case RVA isn't accessible 
                    try:
                        pe = pefile.PE(data=data)
                    except:
                        print "Error: pefile cannot parse the data as a PE (not malicious per se, but maybe you should check): %s" % rebuilt_name
                        continue
                        
                    # misc feature to alert on any PE files with TLS entries
                    if (hasattr(pe, 'DIRECTORY_ENTRY_TLS') and pe.DIRECTORY_ENTRY_TLS and pe.DIRECTORY_ENTRY_TLS.struct):
                        print "TLS directory present in %s, check for anti-debugging" % path
                        
                    # start the IAT hook detection by making sure the IAT is accessible 
                    if (hasattr(pe, 'DIRECTORY_ENTRY_IMPORT')): 
                        
                        # loop once for each of the imported DLLs
                        for module in pe.DIRECTORY_ENTRY_IMPORT:
                
                            # get a list of the DLLs in the process space that match the name of the imported DLL. 
                            # this is important, for example, because a process might load comctl32.dll from both
                            # the system32 directory and the WinSxS directory for app compatibility  
                            modlist = get_modlist(p, module.dll.lower())
                            if len(modlist) == 0:
                                print "Error: Cannot find any loaded modules matching %s" % module.dll.lower()
                                continue
                                
                            # loop once for each of the imported functions in the DLL
                            for symbol in module.imports:
                                if symbol.import_by_ordinal is True:
                                    continue
                                    
                                if symbol.bound:
                                    
                                    # check to see if the imported function address points within one of the DLLs with a matching name
                                    found = False
                                    for m in modlist:
                                        if inside_module(m.base, m.size, symbol.bound):
                                            found = True
                                            break
                                    
                                    # figure out where the hooked IAT entry points (another DLL or just an allocated heap block?)
                                    if not found:
                                        m = get_module_by_addr(p, symbol.bound)
                                        hooking_module = m.dll_full_path if m is not None else "UNKNOWN"
                                        
                                        if not use_filter or (use_filter and \
                                            # Ignore hooks that point inside C runtime libraries 
                                            ("msvcr" not in hooking_module.lower()) and ("msvcp" not in hooking_module.lower()) and \
                                            # Ignore hooks of WMI* that point inside Advapi32.dll
                                            (("wmi.dll" != module.dll.lower()) and ("advapi32.dll" not in hooking_module.lower())) and \
                                            # Ignore hooks of SCHANNEL* that point inside secur32.dll
                                            (("schannel.dll" != module.dll.lower()) and ("secur32.dll" not in hooking_module.lower())) and \
                                            # Ignore hooks that point inside ntdll.dll
                                            ("ntdll.dll" not in hooking_module.lower()) and \
                                            # Ignore hooks that point inside the Shim Engine - see http://www.alex-ionescu.com/?p=39
                                            ("shimeng.dll" not in hooking_module.lower())):
                                            print "%-8s %-16s %-6s %-40s %s!%-40s [0x%x] => 0x%-16x %-16s" % ("IAT", p.exe_name, p.pid, path, module.dll, symbol.name, symbol.address, symbol.bound, hooking_module)
 
                    # start the EAT and inline hook detection by making sure the EAT is accessible. 
                    # not every module has an EAT, so this first audit message can be noisy (uncomment if you still want to know)
                    if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                        #print "Skipping EAT and inline hooks for %s because it has no EAT" % rebuilt_name
                        continue
                        
                    # loop once for each exported function
                    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                        
                        # use the export ordinal if the name isn't available
                        if exp.name is None or exp.name == "":
                            exp.name = exp.ordinal
                            
                        export_va  = (base + exp.address) & 0xffffffff
                        
                        if (export_va < base) or (export_va > base+size):
                            m = get_module_by_addr(p, export_va)
                            hooking_module = m.dll_full_path if m is not None else "UNKNOWN"
                            print "%-8s %-16s %-6s %-40s %-32s 0x%-16x %-16s" % ("EAT", p.exe_name, p.pid, path, exp.name, export_va, hooking_module)
                            continue # don't try to disassemble a hooked EAT function - the VA won't be available
                            
                        # disassemble the first 2 instructions of the prologue
                        prologue = pe.get_data(exp.address, 24)
                        
                        i1 = pydasm.get_instruction(prologue, pydasm.MODE_32)
                        if not i1:
                            continue
                            
                        i2 = pydasm.get_instruction(prologue[i1.length:], pydasm.MODE_32)
                        if not i2:
                            continue 
                        
                        hook_destination = None
                            
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
                            
                        if hook_destination is not None:

                            if not inside_module(base, size, hook_destination):
                                
                                m = get_module_by_addr(p, hook_destination)
                                hooking_module = m.dll_full_path if m is not None else "UNKNOWN"
                                
                                if not use_filter or (use_filter and \
                                    # Ignore hooks of hooks in Microsoft C runtime libraries - almost all are hooked by default
                                    not path.split('\\')[-1].lower().startswith('msvcp') and \
                                    not path.split('\\')[-1].lower().startswith('msvcr')):
                                    print "%-8s %-16s %-6s %-40s %-40s 0x%x => %-16s %-16s" % ("INLINE", p.exe_name, p.pid, path, exp.name, export_va, instruction, hooking_module)
        
        # delete all the dumped exe and dll files. comment this out to keep them for later analysis
        shutil.rmtree(outdir)


