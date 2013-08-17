#!/usr/bin/env python
#
# exportstack.py
# Copyright (C) 2010, 2013 Carl Pulley <c.j.pulley@hud.ac.uk>
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
Code to parse and search _ETHREAD stacks.

Based on preliminary work done by Carl Pulley for Honeynet Challenge 3 (Banking Troubles).

@author:       Carl Pulley
@license:      GNU General Public License 2.0 or later
@contact:      c.j.pulley@hud.ac.uk
@organization: University of Huddersfield

DEPENDENCIES:
  distorm3
  yara

REFERENCES:
[1] Russinovich, M., Solomon, D.A. & Ionescu, A. (2009). Windows Internals: 
    Including Windows Server 2008 and Windows Vista, Fifth Edition (Pro 
    Developer) 5th ed. Microsoft Press.
[2] Hewardt, M. & Pravat, D. (2007). Advanced Windows Debugging 1st ed. 
    Addison-Wesley Professional.
[3] Ligh, M., H. (2011). Investigating Windows Threads with Volatility. Retrieved 
    from:
      http://mnin.blogspot.com/2011/04/investigating-windows-threads-with.html
[4] Ionescu, A. (2008). Part 1: Processes, Threads, Fibers and Jobs. Retrieved 
    from:
      http://www.alex-ionescu.com/BH08-AlexIonescu.pdf
[5] Windows Data Alignment on IPF, x86, and x64 (2006). Retrieved from:
      http://msdn.microsoft.com/en-us/library/aa290049(v=vs.71).aspx
[6] Deyblue, A. (2009). Grabbing Kernel Thread Call Stacks the Process Explorer Way. 
    Retrived from:
      http://blog.airesoft.co.uk/2009/02/grabbing-kernel-thread-contexts-the-process-explorer-way/
[7] Litchfield, D. (2003). Defeating the Stack Based Buffer Overflow Prevention 
    Mechanism of Microsoft Windows 2003 Server. Retrieved from:
      http://www.blackhat.com/presentations/bh-asia-03/bh-asia-03-litchfield.pdf
[8] Bray, B. (2002). Compiler Security Checks In Depth. Microsoft. Retrieved from: 
      http://msdn.microsoft.com/en-GB/library/aa290051(v=vs.71).aspx
[9] Miller, M. (2007). Reducing the Effective Entropy of GS Cookies. Uninformed Vol. 7. 
    Retrieved from:
      http://uninformed.org/index.cgi?v=7&a=2&p=5
[10] Jurczyk, M. and Coldwind, G. (2011). Exploiting the otherwise non-exploitable: 
    Windows Kernel-mode GS Cookies subverted. Retrieved from:
      http://vexillium.org/dl.php?/Windows_Kernel-mode_GS_Cookies_subverted.pdf
"""

import bisect
try:
  import distorm3
  distorm3_installed = True
except ImportError:
  distorm3_installed = False
import functools
from inspect import isfunction
import itertools
import os.path
import pydoc
import sys
import volatility.debug as debug
import volatility.obj as obj
import volatility.plugins.malware.threads as threads
import volatility.plugins.overlays.windows.pe_vtypes as pe_vtypes
import volatility.plugins.overlays.windows.windows as windows
import volatility.plugins.symbols as symbols
import volatility.registry as registry
import volatility.utils as utils
import volatility.plugins.vadinfo as vadinfo
import volatility.win32.modules as sysmods
import volatility.win32.tasks as tasks
try:
    import yara
    yara_installed = True
except ImportError:
    yara_installed = False

DEFAULT_UNWIND = "EBP,CALL_RET,EXCEPTION_REGISTRATION_RECORD"

#--------------------------------------------------------------------------------
# unwind classes
#--------------------------------------------------------------------------------

class StackTop(object):
  """Abstract class that represents the top of the stack"""
  def __init__(self, start, stack_base, stack_limit, eproc, *args, **kwargs):
    if isfunction(start):
      self.start = start(self.__class__.__name__)
    else:
      self.start = start
    self.stack_base = stack_base
    self.stack_limit = stack_limit
    self.eproc = eproc
    self.addrspace = eproc.get_process_address_space()
    self.alignment = 4 if self.addrspace.profile.metadata.get('memory_model', '32bit') == '32bit' else 16
    self.caller = None

  def up(self):
    """Stack iterator that retrieves stack frames above this one"""
    return []

  def down(self):
    """Stack iterator that retrieves stack frames below and including this one"""
    return [self]

  def __repr__(self):
    return "{0:#010x}".format(self.start)

  def exec_addr(self):
    return "RET: {0:#010x}".format(self.caller) if self.caller != None else "-"*10

class UserFrame(StackTop): 
  """User stack unwind strategy - user code should extend this class"""
  pass

class KernelFrame(StackTop): 
  """Kernel stack unwind strategy - user code should extend this class"""
  pass

# TODO: add in 64bit stack unwinding

class EBP(UserFrame, KernelFrame):
  """
  EBP (-> *EBP)    RET: *(EBP+4)    symbol_lookup(*(EBP+4))
  Represents an x86 EBP/EIP stack frame unwind
  """
  def __init__(self, start, stack_base, stack_limit, eproc, *args, **kwargs):
    StackTop.__init__(self, start, stack_base, stack_limit, eproc, *args, **kwargs)
    self.ebp = self.start
    if self.addrspace.is_valid_address(self.ebp):
      self.next_ebp = self.addrspace.read_long_phys(self.addrspace.vtop(self.ebp))
    else:
      self.next_ebp = obj.NoneObject("Invalid stack frame address: EBP={0:#x}".format(self.ebp))
    if self.addrspace.is_valid_address(self.ebp + self.alignment):
      self.eip = self.addrspace.read_long_phys(self.addrspace.vtop(self.ebp + self.alignment))
    else:
      self.eip = obj.NoneObject("Invalid stack frame address: EBP{1:+#x}={0:#x}".format(self.ebp + self.alignment, self.alignment))
    self.caller = self.eip

  def up(self):
    # Perform a linear search looking for potential (old) EBP chain values in remnants of old stack frames
    frame = self
    # From [5], we assume an alignment for stack frames based on the memory model's bit size
    ebp_ptr = frame.ebp - self.alignment
    ebp_bases = { frame.ebp }
    while self.stack_limit < ebp_ptr and ebp_ptr <= self.stack_base:
      if self.addrspace.is_valid_address(ebp_ptr):
        ebp_value = self.addrspace.read_long_phys(self.addrspace.vtop(ebp_ptr))
        if ebp_value in ebp_bases:
          frame = EBP(ebp_ptr, self.stack_base, self.stack_limit, self.eproc)
          yield frame
          ebp_bases.add(frame.ebp)
      ebp_ptr -= self.alignment
    raise StopIteration

  def down(self):
    # Follow the EBP chain downloads and so locate stack frames
    frame = self
    yield frame
    while self.stack_limit < frame.next_ebp and frame.next_ebp <= self.stack_base:
      if not self.addrspace.is_valid_address(frame.next_ebp):
        raise StopIteration
      frame = EBP(frame.next_ebp, self.stack_base, self.stack_limit, self.eproc)
      yield frame
    raise StopIteration

  def __repr__(self):
    ebp_str = "{:#010x}".format(self.ebp) if self.ebp != None else "-"*10
    next_ebp_str = "{:#010x}".format(self.next_ebp) if self.next_ebp != None else "-"*10
    return "{0} (-> {1})".format(ebp_str, next_ebp_str)

# FIXME: following still needs more work
class GS(EBP):
  """
  EBP (-> *(EBP))    /GS [security_cookie]: *(EBP+4)    symbol_lookup(*(EBP+4))    [*(EBP-4) == security_cookie ^ EBP]
  Detect EBP stack frames with /GS security cookies (originating module determined using EIP)
  """
  # Security cookie calculations prior to cookie saving:
  # WinXP: *(EBP-4) == security_cookie
  # Vista, 2008 and Win7: *(EBP-4) == security_cookie ^ EBP
  def __init__(self, start, stack_base, stack_limit, eproc, modules=None, module_addrs=None, *args, **kwargs):
    EBP.__init__(self, start, stack_base, stack_limit, eproc, *args, **kwargs)
    if modules == None:
      self.modules = dict( (m.DllBase, m) for m in list(sysmods.lsmod(eproc.get_process_address_space())) + list(eproc.get_load_modules()) )
      self.module_addrs = sorted(self.modules.keys())
    else:
      self.modules = modules
      self.module_addrs = module_addrs
    mod = tasks.find_module(self.modules, self.module_addrs, self.eip)
    self.security_cookie = None
    self.cookie = None
    security_cookie_addr = None
    if mod != None:
      load_config = mod.get_load_config_directory()
      if load_config == None:
        # Attempt to use PDB symbols to locate this module's ___security_cookie
        addrs = eproc.lookup("{0}/.data!___security_cookie".format(str(mod.BaseDllName)))
        if len(addrs) > 0:
          security_cookie_addr = addrs[0]
      else:
        # Use _IMAGE_LOAD_CONFIG_DIRECTORY to locate this module's ___security_cookie
        security_cookie_addr = self.addrspace.vtop(load_config.SecurityCookie)
      if security_cookie_addr != None and self.addrspace.is_valid_address(security_cookie_addr):
        self.security_cookie = self.addrspace.read_long_phys(self.addrspace.vtop(security_cookie_addr))
      if self.addrspace.is_valid_address(self.ebp - self.alignment):
        self.cookie = self.addrspace.read_long_phys(self.addrspace.vtop(self.ebp - self.alignment))

  def cookie_check(self):
    return self.ebp ^ self.cookie == self.security_cookie

  def up(self):
    for frame in EBP.up(self):
      yield GS(frame.start, frame.stack_base, frame.stack_limit, frame.eproc, modules=self.modules, module_addrs=self.module_addrs)
    raise StopIteration

  def down(self):
    for frame in EBP.down(self):
      yield GS(frame.start, frame.stack_base, frame.stack_limit, frame.eproc, modules=self.modules, module_addrs=self.module_addrs)
    raise StopIteration

  def __repr__(self):
    if self.security_cookie != None:
      if self.cookie != None:
        if self.cookie_check():
          return "/GS [True]"
        else:
          return "/GS False [{0:#010x} ^ {1:#010x} != {2:#010x}]".format(self.ebp, self.cookie, self.security_cookie)
      else:
        return "/GS ???? [UNREADABLE]".format(self.security_cookie)
    else:
      return "no /GS"

class EXCEPTION_REGISTRATION_RECORD(UserFrame):
  """
  EXN (-> EXN.Next)    Handler: EXN.Handler    symbol_lookup(EXN.Handler)
  Represents an _EXCEPTION_REGISTRATION_RECORD stack frame unwind
  """
  def __init__(self, start, stack_base, stack_limit, eproc, *args, **kwargs):
    UserFrame.__init__(self, start, stack_base, stack_limit, eproc, *args, **kwargs)
    if self.addrspace.is_valid_address(self.start):
      self.exn = obj.Object('_EXCEPTION_REGISTRATION_RECORD', self.start, self.addrspace)
    else:
      self.exn = obj.NoneObject("Invalid exception frame address: {0:#x}".format(self.start))
    self.caller = self.exn.Handler.v()

  def up(self):
    # Perform a linear search looking for potential (old) _EXCEPTION_REGISTRATION_RECORD Next values in remnants of old exception frames
    frame = self
    exn_ptr = self.exn.v() - self.alignment
    exn_bases = { frame.exn.v() }
    while self.stack_limit < exn_ptr and exn_ptr <= self.stack_base:
      if self.addrspace.is_valid_address(exn_ptr):
        exn = obj.Object('_EXCEPTION_REGISTRATION_RECORD', exn_ptr, self.addrspace)
        if exn.Next.v() in exn_bases:
          frame = EXCEPTION_REGISTRATION_RECORD(exn.v(), self.stack_base, self.stack_limit, self.eproc)
          yield frame
          exn_bases.add(frame.exn.v())
      exn_ptr -= self.alignment
    raise StopIteration

  def down(self):
    # Follow _EXCEPTION_REGISTRATION_RECORD Next pointers and so locate exception frames
    frame = self
    yield frame
    while self.stack_limit < frame.exn.Next and frame.exn.Next <= self.stack_base:
      if not self.addrspace.is_valid_address(frame.exn.Next):
        raise StopIteration
      frame = EXCEPTION_REGISTRATION_RECORD(frame.exn.Next.v(), self.stack_base, self.stack_limit, self.eproc)
      yield frame
    raise StopIteration

  def __repr__(self):
    exn_str = "{0:#010x}".format(self.exn.v()) if self.exn != None else "-"
    exn_next_str = "{0:#010x}".format(self.exn.Next.v()) if self.exn != None else "-"
    return "{0} (-> {1})".format(exn_str, exn_next_str)

  def exec_addr(self):
    return "Handler: " + ("{0:#010x}".format(self.caller) if self.caller != None else "-"*10)

def get_page_nx_bit(addrspace, addr):
  pdpte = addrspace.get_pdpte(addr)
  pde = addrspace.get_pde(addr, pdpte)
  pte = addrspace.get_pte(addr, pde)
  return pte >> 63

class PAGE_EXECUTE(UserFrame, KernelFrame):
  """
  ADDR    RET: *(ADDR)    symbol_lookup(*(ADDR))    [NX not in page_permissions(*(ADDR))]
  Stack addresses belonging to memory pages with NX bit unset
  """
  def __init__(self, start, stack_base, stack_limit, eproc, ret_addr=None, *args, **kwargs):
    StackTop.__init__(self, start, stack_base, stack_limit, eproc, *args, **kwargs)
    assert self.addrspace.pae
    if ret_addr == None:
      self.caller = obj.NoneObject("No return address specified")
    else:
      self.caller = ret_addr

  def check(self, addr):
    return get_page_nx_bit(self.addrspace, addr) == 0

  def up(self):
    addr_ptr = self.start - self.alignment
    while self.stack_limit < addr_ptr and addr_ptr <= self.stack_base:
      if self.addrspace.is_valid_address(addr_ptr):
        ret_addr = self.addrspace.read_long_phys(self.addrspace.vtop(addr_ptr))
        if self.check(ret_addr):
          yield PAGE_EXECUTE(addr_ptr, self.stack_base, self.stack_limit, self.eproc, ret_addr)
      addr_ptr -= self.alignment
    raise StopIteration

  def down(self):
    addr_ptr = self.start
    while self.stack_limit < addr_ptr and addr_ptr <= self.stack_base:
      if self.addrspace.is_valid_address(addr_ptr):
        ret_addr = self.addrspace.read_long_phys(self.addrspace.vtop(addr_ptr))
        if self.check(ret_addr):
          yield PAGE_EXECUTE(addr_ptr, self.stack_base, self.stack_limit, self.eproc, ret_addr)
      addr_ptr += self.alignment
    raise StopIteration

# How far to search for a straight-line code/RET instruction sequence (i.e. ROP gadget)
MAX_GADGET_SIZE = 256

# FIXME: following needs some testing
class Gadget(PAGE_EXECUTE):
  """
  ADDR    ROP [len(GADGET)]: *(ADDR)    symbol_lookup(*(ADDR))    [PAGE_EXECUTE(*(ADDR)); GADGET == "instr1; ..; RET"]
  Gagets are stack addresses belonging to PAGE_EXECUTE memory pages, with return addresses that are 
  non-trivial code blocks ending in a RET instruction.
  """
  def __init__(self, start, stack_base, stack_limit, eproc, rop_size=0, *args, **kwargs):
    if not distorm3_installed:
      debug.error("In order to work with ROP Gadget's, you need to install distorm3")
    PAGE_EXECUTE.__init__(self, start, stack_base, stack_limit, eproc, *args, **kwargs)

    memory_model = self.addrspace.profile.metadata.get('memory_model', '32bit')
    if memory_model == '32bit':
      self.mode = distorm3.Decode32Bits
    else:
      self.mode = distorm3.Decode64Bits
    self.rop_size = rop_size

  def check(self, addr):
    max_mem_addr = (2**32 if self.mode == distorm3.Decode32Bits else 2**64) - 1
    max_gadget_size = min(MAX_GADGET_SIZE, max_mem_addr - addr)
    if max_gadget_size == 0:
      return False
    code = self.addrspace.zread(addr, max_gadget_size)
    for op in distorm3.DecomposeGenerator(addr, code, self.mode, features=distorm3.DF_RETURN_FC_ONLY):
      if not op.valid:
        continue
      if self.rop_size > 0 and op.flowControl == 'FC_RET':
        self.rop_size = addr - op.address
        return True
      else:
        return False
    return False

  def up(self):
    for frame in PAGE_EXECUTE.up(self):
      if self.check(frame.caller):
        yield Gadget(frame.start, frame.stack_base, frame.stack_limit, frame.eproc, rop_size=self.rop_size)
    raise StopIteration

  def down(self):
    for frame in PAGE_EXECUTE.down(self):
      if self.check(frame.caller):
        yield Gadget(frame.start, frame.stack_base, frame.stack_limit, frame.eproc, rop_size=self.rop_size)
    raise StopIteration

  def exec_addr(self):
    return "ROP [{0:#x} B]: ".format(self.rop_size) + ("{0:#010x}".format(self.caller) if self.caller != None else "-"*10)

class CALL_RET(PAGE_EXECUTE):
  """
  ADDR (CALL xxx)    RET: xxx    symbol_lookup(xxx)    [PAGE_EXECUTE(ADDR); *(ADDR-size(CALL xxx)) == CALL xxx]
  Any stack address that belongs to an executable page (i.e. a RET address) and has a CALL 
  instruction as its prior instruction is taken to be a CALL/RET frame.
  """
  def __init__(self, start, stack_base, stack_limit, eproc, instr=None, caller=None, *args, **kwargs):
    if not distorm3_installed:
      debug.error("In order to detect CALL/RET frames, you need to install distorm3")
    PAGE_EXECUTE.__init__(self, start, stack_base, stack_limit, eproc, *args, **kwargs)

    memory_model = self.addrspace.profile.metadata.get('memory_model', '32bit')
    if memory_model == '32bit':
      self.mode = distorm3.Decode32Bits
    else:
      self.mode = distorm3.Decode64Bits
    self.caller = caller
    self.instr = instr

  def check(self, addr):
    self.caller = None
    self.instr = None
    if addr == None:
      return False
    # We only need the last 16 bytes, since this is the largest size the (prior) x86 instruction can be
    code = self.addrspace.zread(addr-16, 16)
    for size in range(0, 16):
      instrs = distorm3.Decompose(addr-size-1, code[-(size+1):], self.mode)
      op = instrs[-1]
      if not op.valid:
        continue
      if op.flowControl == 'FC_NONE':
        return False
      if op.flowControl == 'FC_CALL':
        self.instr = op
        # if the CALL instruction has a determinate target, set caller to it
        if [ o.type for o in op.operands ] == ["Immediate"]:
          self.caller = op.operands[0].value
        elif [ o.type for o in op.operands ] == ["AbsoluteMemoryAddress"]:
          self.caller = self.start + op.disp
        return True
    return False

  def up(self):
    for frame in PAGE_EXECUTE.up(self):
      if self.check(frame.caller):
        yield CALL_RET(frame.start, frame.stack_base, frame.stack_limit, frame.eproc, instr=self.instr, caller=self.caller)
    raise StopIteration

  def down(self):
    for frame in PAGE_EXECUTE.down(self):
      if self.check(frame.caller):
        yield CALL_RET(frame.start, frame.stack_base, frame.stack_limit, frame.eproc, instr=self.instr, caller=self.caller)
    raise StopIteration

  def exec_addr(self):
    if self.caller != None:
      return "CALL: {0:#010x}".format(self.caller)
    else:
      return "-"

  def __repr__(self):
    if self.instr != None:
      return "{0:#010x} ({1})".format(self.start, self.instr)
    else:
      return PAGE_EXECUTE.__repr__(self)

#--------------------------------------------------------------------------------
# profile modifications  
#--------------------------------------------------------------------------------

# Extension methods for the profiles EPROCESS (injected by StackModification)
class StackEPROCESS(windows._EPROCESS):
  def search_stack_frames(self, start, stack_base, stack_limit, yara_rules, frame_delta=32,   unwind=DEFAULT_UNWIND):
    """ 
    Use Yara to search kernel/user stack frames within +/- frame_delta of the frame's start  
    address.
  
    Frames to search are chosen by using the strategies specifed by the unwind parameter.
  
    yara_rules - compiled Yara rules, built for example with:
       1. yara.compile("/path/to/yara.rules")
    or 2. yara.compile(source="rule dummy { condition: true }")
    """
  
    if not yara_installed:
      debug.error("In order to search the stack frames, it is necessary to install yara")
  
    stack_registry = registry.get_plugin_classes(StackTop)
    
    for unwind_strategy_nm in unwind.split(","):
      if unwind_strategy_nm not in stack_registry:
        raise ValueError("{0} is not a known stack unwind strategy".format(unwind_strategy_nm))
      unwind_strategy = stack_registry[unwind_strategy_nm](start, stack_base, stack_limit, self)
      for frame in itertools.chain(unwind_strategy.up(), unwind_strategy.down()):
        search_data = self.get_process_address_space().zread(frame.start - frame_delta, 2* frame_delta)
        for match in yara_rules.match(data = search_data):
          for moffset, name, value in match.strings:
            # Match offset here is converted into frame start address and a +/- frame_delta
            yield match, name, value, frame.start, moffset-frame_delta
  
    raise StopIteration

class StackLDR_DATA_TABLE_ENTRY(pe_vtypes._LDR_DATA_TABLE_ENTRY):
  def load_config(self):
    """Return the IMAGE_LOAD_CONFIG_DIRECTORY for load config"""
    return self._directory(10) # IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG

  def get_load_config_directory(self):
    """Return the load config object for this PE"""
    try:
      load_config = self.load_config()
    except ValueError, why:
      return obj.NoneObject(str(why))

    return obj.Object("_IMAGE_LOAD_CONFIG_DIRECTORY", offset=self.DllBase + load_config.VirtualAddress, vm=self.obj_native_vm)

class StackModification(obj.ProfileModification):
  before = ["WindowsObjectClasses"]

  conditions = {'os': lambda x: x == 'windows'}

  def modification(self, profile):
    for func in StackEPROCESS.__dict__:
      if isfunction(StackEPROCESS.__dict__[func]):
        setattr(profile.object_classes['_EPROCESS'], func, StackEPROCESS.__dict__[func])
    for func in StackLDR_DATA_TABLE_ENTRY.__dict__:
      if isfunction(StackLDR_DATA_TABLE_ENTRY.__dict__[func]):
        setattr(profile.object_classes['_LDR_DATA_TABLE_ENTRY'], func, StackLDR_DATA_TABLE_ENTRY.__dict__[func])

class StackModification32bit(obj.ProfileModification):
  conditions = {'os': lambda x: x == 'windows', 'memory_model': lambda x: x == '32bit'}

  def modification(self, profile):
    profile.vtypes.update({
      '_IMAGE_LOAD_CONFIG_DIRECTORY': [ 0x48, {
      'Size': [ 0x0, ['unsigned int']],
      'TimeDateStamp': [ 0x4, ['unsigned int']],
      'MajorVersion': [ 0x8, ['unsigned short']],
      'MinorVersion': [ 0xa, ['unsigned short']],
      'GlobalFlagsClear': [ 0xc, ['unsigned int']],
      'GlobalFlagsSet': [ 0x10, ['unsigned int']],
      'CriticalSectionDefaultTimeout': [ 0x14, ['unsigned int']],
      'DeCommitFreeBlockThreshold': [ 0x18, ['unsigned int']],
      'DeCommitTotalFreeThreshold': [ 0x1c, ['unsigned int']],
      'LockPrefixTable': [ 0x20, ['unsigned int']],
      'MaximumAllocationSize': [ 0x24, ['unsigned int']],
      'VirtualMemoryThreshold': [ 0x28, ['unsigned int']],
      'ProcessHeapFlags': [ 0x2c, ['unsigned int']],
      'ProcessAffinityMask': [ 0x30, ['unsigned int']],
      'CSDVersion': [ 0x34, ['unsigned short']],
      'Reserved1': [ 0x36, ['unsigned short']],
      'EditList': [ 0x38, ['unsigned int']],
      'SecurityCookie': [ 0x3c, ['unsigned int']], # pointer to ___security_cookie
      'SEHandlerTable': [ 0x40, ['unsigned int']],
      'SEHandlerCount': [ 0x44, ['unsigned int']],
      }],
    })

class StackModification64bit(obj.ProfileModification):
  conditions = {'os': lambda x: x == 'windows', 'memory_model': lambda x: x == '64bit'}
  
  def modification(self, profile):
    profile.vtypes.update({
      '_IMAGE_LOAD_CONFIG_DIRECTORY': [ 0x74, {
      'Size': [ 0x0, ['unsigned int']],
      'TimeDateStamp': [ 0x4, ['unsigned int']],
      'MajorVersion': [ 0x8, ['unsigned short']],
      'MinorVersion': [ 0xa, ['unsigned short']],
      'GlobalFlagsClear': [ 0xc, ['unsigned int']],
      'GlobalFlagsSet': [ 0x10, ['unsigned int']],
      'CriticalSectionDefaultTimeout': [ 0x14, ['unsigned int']],
      'DeCommitFreeBlockThreshold': [ 0x1c, ['unsigned long long']],
      'DeCommitTotalFreeThreshold': [ 0x24, ['unsigned long long']],
      'LockPrefixTable': [ 0x2c, ['unsigned long long']],
      'MaximumAllocationSize': [ 0x34, ['unsigned long long']],
      'VirtualMemoryThreshold': [ 0x3c, ['unsigned long long']],
      'ProcessAffinityMask': [ 0x44, ['unsigned long long']],
      'ProcessHeapFlags': [ 0x4c, ['unsigned int']],
      'CSDVersion': [ 0x50, ['unsigned short']],
      'Reserved1': [ 0x52, ['unsigned short']],
      'EditList': [ 0x54, ['unsigned long long']],
      'SecurityCookie': [ 0x5c, ['unsigned long long']],
      'SEHandlerTable': [ 0x64, ['unsigned long long']],
      'SEHandlerCount': [ 0x6c, ['unsigned long long']],
      }],
    })

#--------------------------------------------------------------------------------
# main plugin code
#--------------------------------------------------------------------------------

class ExportStack(threads.Threads):
  """
  This plugin is an extension of Michael Hale Ligh's threads plugin (see
  http://code.google.com/p/volatility/wiki/CommandReference).

  Given a PID or _EPROCESS object (kernel address), display information 
  regarding the user and kernel stacks, etc. for the processes threads.

  Support is provided for: EBP chains; PAGE_EXECUTE; ROP Gadgets; EBP frames 
  with /GS information; CALL/RET frames; and _EXCEPTION_REGISTRATION_RECORD 
  unwinds. Alternative unwind strategies are easily added.

  By default, EBP chains, CALL/RET frames and _EXCEPTION_REGISTRATION_RECORD 
  unwinds are performed.

  Where possible, executable stack addresses are resolved to module and function 
  names using the symbols.Symbols plugin.
  """

  def __init__(self, config, *args, **kwargs):
    threads.Threads.__init__(self, config, *args, **kwargs)

    if not yara_installed:
      debug.warning("In order to search the stack frames, it is necessary to install yara - searching is disabled")

    config.add_option('UNWIND', default = DEFAULT_UNWIND, help = 'List of frame unwinding strategies (comma-separated)', action = 'store', type = 'str')
    config.add_option('LISTUNWINDS', default = False, help = 'List all known frame unwinding strategies', action = 'store_true')
    config.add_option("SYMBOLS", default = False, action = 'store_true', cache_invalidator = False, help = "Use symbol servers to resolve process addresses to module names (we assume symbol tables have already been built)")

    stack_registry = registry.get_plugin_classes(StackTop)

    if getattr(config, 'LISTUNWINDS', False):
      print "Stack Frame Unwind Strategies:\n"
      for cls_name, cls in sorted(stack_registry.items(), key=lambda v: v[0]):
        if cls_name not in ["UserFrame", "KernelFrame"]:
          print "{0:<20}: {1}\n".format(cls_name, pydoc.getdoc(cls))
      sys.exit(0)

    self.kernel_strategies = []
    self.user_strategies = []
    for strategy in getattr(config, 'UNWIND', DEFAULT_UNWIND).split(","):
      if ":" in strategy:
        if strategy.startswith("kernel:"):
          strategy = strategy[len("kernel:"):]
          if strategy not in stack_registry or not issubclass(stack_registry[strategy], KernelFrame):
            debug.error("{0} is not a valid kernel stack unwinding strategy".format(strategy))
          self.kernel_strategies.append(stack_registry[strategy])
        elif strategy.startswith("user:"):
          strategy = strategy[len("user:"):]
          if strategy not in stack_registry or not issubclass(stack_registry[strategy], UserFrame):
            debug.error("{0} is not a valid user stack unwinding strategy".format(strategy))
          self.user_strategies.append(stack_registry[strategy])
        else:
          debug.error("{0} is an unrecognised stack".format(strategy.split(":")[0]))
      elif strategy not in stack_registry:
        debug.error("{0} is neither a valid kernel nor user stack unwinding strategy".format(strategy))
      elif not issubclass(stack_registry[strategy], KernelFrame) and not issubclass(stack_registry[strategy], UserFrame):
        debug.error("{0} is neither a valid kernel nor stack unwinding strategy".format(strategy))
      else:
        if issubclass(stack_registry[strategy], KernelFrame):
          self.kernel_strategies.append(stack_registry[strategy])
        if issubclass(stack_registry[strategy], UserFrame):
          self.user_strategies.append(stack_registry[strategy])

    self.use_symbols = getattr(config, 'SYMBOLS', False)

    # Determine which filters the user wants to see
    if getattr(config, 'FILTER', None):
      self.filters = set(config.FILTER.split(','))
    else:
      self.filters = set()

  def render_text(self, outfd, data):
    kernel_start = 0 #self.kdbg.MmSystemRangeStart.dereference_as("Pointer")

    for thread, addr_space, system_mods, system_mod_addrs, instances, hooked_tables, system_range, owner_name in data:
      # If the user didn't set filters, display all results. If 
      # the user set one or more filters, only show threads 
      # with matching results. 
      tags = set([t for t, v in instances.items() if v.check()])

      if len(self.filters) > 0 and not self.filters & tags:
        continue

      threads.Threads.render_text(self, outfd, [(thread, addr_space, system_mods, system_mod_addrs, instances, hooked_tables, system_range, owner_name)])
      self.carve_thread(outfd, thread, kernel_start)

  def check_for_exec_stack(self, stack_base, stack_limit, addrspace):
    exec_pages = []
    for page in range(stack_base, stack_limit, 0x1000):
      if get_page_nx_bit(addrspace, page) == 0:
        exec_pages.append(page)
    return exec_pages

  def unwind_stack(self, outfd, sym_lookup, stack_frames):
    self.table_header(outfd, [
      ('Frame', '<14'),
      ("Type", "<12"),
      ('Representation', '<50'),
      ('Executable Address', '<32'),
      ("Module", "<")
    ])
    for number, (addr, frames) in stack_frames:
      if number == 0:
        frame_number = "current"
      else:
        frame_number = "current{0:+}".format(number)
      for frame in frames:
        module_name = sym_lookup(frame.caller)
        self.table_row(outfd, frame_number, frame.__class__.__name__, repr(frame), frame.exec_addr(), module_name)

  def unwind_strategy(self, unwind_strategies, start, stack_base, stack_limit, eproc):
    frames_up = list((a, list(fs)) for a, fs in itertools.groupby(sorted([ frame for strategy in unwind_strategies for frame in strategy(start, stack_base, stack_limit, eproc).up() ], key=lambda f: f.start, reverse=True), lambda f: f.start))
    frames_down = list((a, list(fs)) for a, fs in itertools.groupby(sorted([ frame for strategy in unwind_strategies for frame in strategy(start, stack_base, stack_limit, eproc).down() ], key=lambda f: f.start), lambda f: f.start))
    if len(frames_down) > 0 and frames_down[0][0] == start:
      frames_down = [ (start, [StackTop(start, stack_base, stack_limit, eproc)] + frames_down[0][1]) ] + frames_down[1:]
    else:
      frames_down = [ (start, [StackTop(start, stack_base, stack_limit, eproc)]) ] + frames_down
    return list(reversed(list(enumerate(frames_up, start=1)))) + [ (-n, f) for n, f in enumerate(frames_down, start=0) ]

  def carve_thread(self, outfd, thread, kernel_start):
    trap_frame = thread.Tcb.TrapFrame.dereference_as("_KTRAP_FRAME")
    process_addrspace = thread.owning_process().get_process_address_space()
    eproc = thread.owning_process()

    #outfd.write("\n")

    #outfd.write("Kernel Start Address: {0:#010x}\n".format(kernel_start))

    outfd.write("\n")
    kstack_base = thread.Tcb.InitialStack.v()
    kstack_limit = thread.Tcb.StackLimit.v()
    outfd.write("Kernel Stack:\n")
    outfd.write("  Range: {0:#08x}-{1:#08x}\n".format(kstack_limit, kstack_base))
    outfd.write("  Size: {0:#x}\n".format(kstack_base - kstack_limit))
    exec_pages = self.check_for_exec_stack(kstack_base, kstack_limit, process_addrspace)
    if len(exec_pages) > 0:
      outfd.write("Kernel Stack has pages marked as EXECUTABLE\n")
    esp = thread.Tcb.KernelStack.v()
    if thread.Tcb.KernelStackResident and process_addrspace.is_valid_address(esp+12) and kstack_limit < kstack_base:
      outfd.write("<== Kernel Stack Unwind ==>\n")
      # See [6] for how EBP is saved on the kernel stack and the reason for a magic value of 12
      ebp = process_addrspace.read_long_phys(process_addrspace.vtop(esp+12))
      self.unwind_stack(outfd, functools.partial(eproc.lookup, use_symbols=self.use_symbols), self.unwind_strategy(self.kernel_strategies, ebp, kstack_base, kstack_limit, eproc))
      outfd.write("<== End Kernel Stack Unwind ==>\n")
    elif not thread.Tcb.KernelStackResident:
      outfd.write("Kernel stack is not resident\n")

    teb = obj.Object('_TEB', offset = thread.Tcb.Teb.v(), vm = process_addrspace)

    outfd.write("\n")
    if teb.is_valid():
      ustack_base = teb.NtTib.StackBase.v()
      ustack_limit = teb.NtTib.StackLimit.v()
      outfd.write("User Stack:\n")
      outfd.write("  Range: {0:#08x}-{1:#08x}\n".format(ustack_limit, ustack_base))
      outfd.write("  Size: {0:#x}\n".format(ustack_base - ustack_limit))
      exec_pages = self.check_for_exec_stack(ustack_base, ustack_limit, process_addrspace)
      if len(exec_pages) > 0:
        outfd.write("User Stack has pages marked as EXECUTABLE\n")
      if trap_frame.is_valid() and ustack_limit < ustack_base:
        outfd.write("<== User Stack Unwind ==>\n")
        def start_func(frame_class_name):
          if frame_class_name == "EXCEPTION_REGISTRATION_RECORD":
            teb = obj.Object('_TEB', thread.Tcb.Teb.v(), process_addrspace)
            return teb.NtTib.ExceptionList.v()
          else:
            return trap_frame.Ebp
        self.unwind_stack(outfd, functools.partial(eproc.lookup, use_symbols=self.use_symbols), self.unwind_strategy(self.user_strategies, start_func, ustack_base, ustack_limit, eproc))
        outfd.write("<== End User Stack Unwind ==>\n")
      elif not trap_frame.is_valid():
        outfd.write("User Trap Frame is Invalid\n")
    else:
      outfd.write("User Stack:\n")
      outfd.write("  TEB has been paged out?\n")
