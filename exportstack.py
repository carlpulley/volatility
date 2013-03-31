#!/usr/bin/env python
#
# exportfile.py
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
This plugin displays information regarding an _EPROCESS'es thread data structures

@author:       Carl Pulley
@license:      GNU General Public License 2.0 or later
@contact:      c.j.pulley@hud.ac.uk
@organization: University of Huddersfield
"""

import re
import os.path
try:
  import distorm3
  distorm3_installed = True
except ImportError:
  distorm3_installed = False
import volatility.utils as utils
import volatility.obj as obj
import volatility.win32.tasks as tasks
import volatility.debug as debug
import volatility.commands as commands
import volatility.plugins.malware.threads as threads

class ExportStack(threads.Threads):
  """
  This plugin is an extension of Michael Hale Ligh's threads plugin (see
  http://code.google.com/p/volatility/wiki/CommandReference).

  Given a PID or _EPROCESS object (kernel address), display information 
  regarding the various stacks, registers, etc. for the processes threads.
  
  User/kernel stack unwinding functions by attempting to follow the EBP 
  register entries in each stack frame. Unwinding occurs in both an upwards 
  (i.e. stack decrementation on x86) and a downwards direction (i.e. stack 
  incrementation on x86). Attempts are made to unwind: the user exception 
  stack; and both the user and kernel stacks. 

  NOTE: FPO (Frame Pointer Optimisation) or similar techniques cause this 
  code to produce unreliable stack unwinds.
  
  REFERENCES:
  [1] Russinovich, M., Solomon, D.A. & Ionescu, A., 2009. Windows Internals: 
      Including Windows Server 2008 and Windows Vista, Fifth Edition (Pro 
      Developer) 5th ed. Microsoft Press.
  [2] Hewardt, M. & Pravat, D., 2007. Advanced Windows Debugging 1st ed. 
      Addison-Wesley Professional.
  [3] Investigating Windows Threads with Volatility (accessed 13/Oct/2011):
      http://mnin.blogspot.com/2011/04/investigating-windows-threads-with.html
  [4] Part 1: Processes, Threads, Fibers and Jobs (accessed 14/Oct/2011):
      http://www.alex-ionescu.com/BH08-AlexIonescu.pdf
  [5] Windows Data Alignment on IPF, x86, and x64 (accessed 20/Mar/2013):
      http://msdn.microsoft.com/en-us/library/aa290049(v=vs.71).aspx
  [6] Grabbing Kernel Thread Call Stacks the Process Explorer Way (accessed 
      20/Mar/2013):
      http://blog.airesoft.co.uk/2009/02/grabbing-kernel-thread-contexts-the-process-explorer-way/
  """

  meta_info = dict(
    author = 'Carl Pulley',
    copyright = 'Copyright (c) 2010, 2013 Carl Pulley',
    contact = 'c.j.pulley@hud.ac.uk',
    license = 'GNU General Public License 2.0 or later',
    url = 'http://compeng.hud.ac.uk/scomcjp',
    os = ['WinXPSP2x86', 'WinXPSP3x86'],
    version = '1.0',
    )

  def render_text(self, outfd, data):
    # Determine which filters the user wants to see
    if self._config.FILTER:
      filters = set(self._config.FILTER.split(','))
    else:
      filters = set()

    for thread, addr_space, mods, mod_addrs, instances, hooked_tables, system_range in data:
      # If the user didn't set filters, display all results. If 
      # the user set one or more filters, only show threads 
      # with matching results. 
      tags = set([t for t, v in instances.items() if v.check()])

      if filters and not filters & tags:
        continue

      threads.Threads.render_text(self, outfd, [(thread, addr_space, mods, mod_addrs, instances, hooked_tables, system_range)])
      self.carve_thread(outfd, thread, addr_space, mods, mod_addrs, instances, hooked_tables, system_range)

  def get_stack_frames(self, addrspace, process_addrspace, start_ebp, stack_base, stack_limit, mode="user"):
    alignment = 4 if addrspace.profile.metadata.get('memory_model', '32bit') == '32bit' else 16

    def stack_frame_iterator_up():
      # Perform a linear search looking for potential (old) EBP chain values in remnants of old stack frames
      ebp = start_ebp
      # From [5], we assume an alignment for stack frames based on the memory model's bit size
      ebp_ptr = start_ebp - alignment
      ebp_bases = { ebp }
      frame_number = 1
      while stack_limit < ebp_ptr and ebp_ptr <= stack_base:
        if process_addrspace.is_valid_address(ebp_ptr):
          ebp_value = process_addrspace.read_long_phys(process_addrspace.vtop(ebp_ptr))
          if ebp_value in ebp_bases:
            next_ebp = ebp_value
            ebp = ebp_ptr
            eip = process_addrspace.read_long_phys(process_addrspace.vtop(ebp_ptr + alignment))
            yield { 'number': frame_number, 'eip': eip, 'ebp': ebp, 'next_ebp': next_ebp }
            ebp_bases.add(ebp)
            frame_number += 1
        ebp_ptr -= alignment
      raise StopIteration
    def stack_frame_iterator_down():
      # Follow the EBP chain downloads and so locate stack frames
      frame_number = 0
      ebp = start_ebp
      while stack_base >= ebp and ebp > stack_limit:
        if not process_addrspace.is_valid_address(ebp):
          eip = None
          yield { 'number': frame_number, 'eip': eip, 'ebp': ebp, 'next_ebp': None }
          raise StopIteration
        eip = process_addrspace.read_long_phys(process_addrspace.vtop(ebp + alignment))
        next_ebp = process_addrspace.read_long_phys(process_addrspace.vtop(ebp))
        yield { 'number': frame_number, 'eip': eip, 'ebp': ebp, 'next_ebp': next_ebp }
        frame_number -= 1
        ebp = next_ebp
      raise StopIteration

    try:
      for frame in stack_frame_iterator_up():
        yield frame
    except topIteration:
      pass
    for frame in stack_frame_iterator_down():
      yield frame
    raise StopIteration

  def get_exception_frames(self, addrspace, process_addrspace, exn_start, stack_base, stack_limit):
    alignment = 4 if addrspace.profile.metadata.get('memory_model', '32bit') == '32bit' else 16

    def exception_iterator_up():
      frame_number = 1
      exn_bases = { exn_start }
      exn_ptr = exn_start - alignment
      while stack_limit < exn_ptr and exn_ptr <= stack_base:
        if process_addrspace.is_valid_address(exn_ptr):
          exn = obj.Object('_EXCEPTION_REGISTRATION_RECORD', exn_ptr, process_addrspace)
          if exn.Next in exn_bases:
            yield { 'number': frame_number, 'exn': exn }
            exn_bases.add(exn)
            frame_number += 1
        exn_ptr -= alignment
      raise StopIteration
    def exception_iterator_down():
      frame_number = 0
      exn = exn_start
      while stack_limit < exn.v() and exn.v() <= stack_base:
        if not process_addrspace.is_valid_address(exn.v()):
          raise StopIteration
        yield { 'number': frame_number, 'exn': exn }
        frame_number -= 1
        exn = exn.Next
      raise StopIteration

    try:
      for frame in exception_iterator_up():
        yield frame
    except StopIteration:
      pass
    for frame in exception_iterator_down():
      yield frame
    raise StopIteration

  def unwind_stack(self, outfd, addr_space, mods, mod_addrs, stack_frames):
    self.table_header(outfd, [
      ('Frame', '<15'),
      ('EIP', '<15'),
      ('Module', '<20'),
      ('EBP (-> Chained Value)', '<')
    ])
    for frame in sorted(stack_frames, key=lambda f: f['number'], reverse=True):
      if frame['number'] == 0:
        frame_number = "current"
      else:
        frame_number = "current{0:+}".format(frame['number'])
      if frame['eip'] is None:
        eip_str = "-"*10
        module_name = "-"
      else:
        eip_str = "{:#08x}".format(frame['eip'])
        module = tasks.find_module(mods, mod_addrs, addr_space.address_mask(frame['eip']))
        if module is not None:
          module_name = str(module.BaseDllName or '-')
        else:
          module_name = "UNKNOWN"
      ebp_str = "{:#08x}".format(frame['ebp']) if frame['ebp'] is not None else "-"*10
      next_ebp_str = "{:#08x}".format(frame['next_ebp']) if frame['next_ebp'] is not None else "-"*10
      self.table_row(outfd, frame_number, eip_str, module_name, "{0} (-> {1})".format(ebp_str, next_ebp_str))

  def unwind_exception_stack(self, outfd, addr_space, mods, mod_addrs, exception_frames):
    self.table_header(outfd, [
      ("Frame", '<15'),
      ("Handler", "[addrpad]"),
      ("Module", "<20"),
      ("Address (-> Next)", "<30")
    ])
    for frame in sorted(exception_frames, key=lambda f: f['number'], reverse=True):
      module = tasks.find_module(mods, mod_addrs, addr_space.address_mask(frame['exn'].Handler.v()))
      if module is not None:
        module_name = str(module.BaseDllName or '-')
      else:
        module_name = "UNKNOWN"
      if frame['number'] == 0:
        frame_number = "current"
      else:
        frame_number = "current{0:+}".format(frame['number'])
      self.table_row(outfd, frame_number, frame['exn'].Handler.v(), module_name, "{0:#08x} (-> {1:#08x})".format(frame['exn'].v(), frame['exn'].Next.v()))

  def carve_thread(self, outfd, thread, addr_space, mods, mod_addrs, instances, hooked_tables, system_range):
    trap_frame = thread.Tcb.TrapFrame.dereference_as("_KTRAP_FRAME")
    process_addrspace = thread.owning_process().get_process_address_space()

    # FIXME: Bodge whilst we wait on issue #397 being resolved?
    mods = dict((addr_space.address_mask(mod.DllBase), mod) for mod in thread.owning_process().get_load_modules())
    mod_addrs = sorted(mods.keys())

    outfd.write("\n")
    kstack_base = thread.Tcb.InitialStack.v()
    kstack_limit = thread.Tcb.StackLimit.v()
    outfd.write("Kernel Stack:\n")
    outfd.write("  Range: {0:#08x}-{1:#08x}\n".format(kstack_limit, kstack_base))
    outfd.write("  Size: {0:#x}\n".format(kstack_base - kstack_limit))
    esp = thread.Tcb.KernelStack.v()
    if thread.Tcb.KernelStackResident and process_addrspace.is_valid_address(esp+12):
      outfd.write("<== Kernel Stack Unwind ==>\n")
      # See [6] for how EBP is saved on the kernel stack and the reason for a magic value of 12
      ebp = process_addrspace.read_long_phys(process_addrspace.vtop(esp+12))
      self.unwind_stack(outfd, addr_space, mods, mod_addrs, self.get_stack_frames(addr_space, process_addrspace, ebp, kstack_base, kstack_limit, mode="kernel"))
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
      if trap_frame.is_valid():
        outfd.write("<== User Stack Unwind ==>\n")
        self.unwind_stack(outfd, addr_space, mods, mod_addrs, self.get_stack_frames(addr_space, process_addrspace, trap_frame.Ebp, ustack_base, ustack_limit))
        outfd.write("<== End User Stack Unwind ==>\n")

        outfd.write("\n")
        outfd.write("<== Exception Stack Unwind ==>\n")
        teb = obj.Object('_TEB', thread.Tcb.Teb.v(), process_addrspace)
        self.unwind_exception_stack(outfd, addr_space, mods, mod_addrs, self.get_exception_frames(addr_space, process_addrspace, teb.NtTib.ExceptionList, ustack_base, ustack_limit))
        outfd.write("<== End Exception Stack Unwind ==>\n")
      else:
        outfd.write("User Trap Frame is Invalid\n")
    else:
      outfd.write("User Stack:\n")
      outfd.write("  TEB has been paged out?\n")
