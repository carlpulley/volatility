#!/usr/bin/env python
#
# exportfile.py
# Copyright (C) 2010 Carl Pulley <c.j.pulley@hud.ac.uk>
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
This plugin implements the exporting and saving of _FILE_OBJECT's

@author:       Carl Pulley
@license:      GNU General Public License 2.0 or later
@contact:      c.j.pulley@hud.ac.uk
@organization: University of Huddersfield
"""

import re
import os.path
try:
	import pydasm
except ImportError:
	print "pydasm is not installed, see http://code.google.com/p/libdasm/ for further information"
import volatility.utils as utils
import volatility.obj as obj
import volatility.win32.tasks as tasks
import volatility.debug as debug
import volatility.commands as commands
import volatility.plugins.filescan as filescan

w32_types = {
	'_W32THREAD' : [ 0x28, { \
		'pEThread' : [ 0x0, ['pointer', ['_ETHREAD']]], \
		'RefCount' : [ 0x4, ['unsigned long'] ], \
		'ptlW32' : [ 0x8, ['pointer', ['void']] ], \
		'pgdiDcattr' : [ 0xc, ['pointer', ['void']] ], \
		'pgdiBrushAttr' : [ 0x10, ['pointer', ['void']] ], \
		'pUMPDObjs' : [ 0x14, ['pointer', ['void']] ], \
		'pUMPDHeap' : [ 0x18, ['pointer', ['void']] ], \
		'dwEngAcquireCount' : [ 0x1c, ['pointer', ['unsigned long']] ], \
		'pSemTable' : [ 0x20, ['pointer', ['void']] ], \
		'pUMPDObj' : [ 0x24, ['pointer', ['void']] ] \
	}]
}

class ExportException(Exception):
	"""General exception for handling warnings and errors during exporting of stacks"""
	pass

class ExportStack(filescan.FileScan):
	"""
	Given a PID, _EPROCESS object (kernel address) or an _ETHREAD object 
	(physical address), display information regarding the various stacks, 
	registers, etc. for the processes threads.
	
	Stack unwinding functions by attempting to follow the EBP register entries 
	in each stack frame. Unwinding occurs in both an upwards (i.e. stack 
	decrementation on x86) and a downwards direction (i.e. stack 
	incrementation on x86). The textual stack unwinding colours the current 
	(i.e. ESP points into this frame) stack frame red. Stack frames above the 
	red or current frame are located via a linear search for EBP chain 
	candidates. Attempts are made to unwind both the user and kernel stacks.
	
	NB: This plugin has functionality overlaps with Michael Hale Ligh's threads 
	plugin (see http://code.google.com/p/volatility/wiki/CommandReference).
	
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
	"""

	meta_info = dict(
		author = 'Carl Pulley',
		copyright = 'Copyright (c) 2010 Carl Pulley',
		contact = 'c.j.pulley@hud.ac.uk',
		license = 'GNU General Public License 2.0 or later',
		url = 'http://compeng.hud.ac.uk/scomcjp',
		os = ['WinXPSP2x86', 'WinXPSP3x86'],
		version = '1.0',
		)

	def __init__(self, config, *args):
		filescan.FileScan.__init__(self, config, *args)
		config.add_option("pid", type = 'int', action = 'store', help = "Export stack information using a given PID")
		config.add_option("eproc", type = 'int', action = 'store', help = "Export stack information using an _EPROCESS offset (kernel address)")
		config.add_option("ethrd", type = 'int', action = 'store', help = "Export stack information using an _ETHREAD offset (physical address)")

	def calculate(self):
		self.kernel_address_space = utils.load_as(self._config)
		self.kernel_address_space.profile.add_types(w32_types)
		self.flat_address_space = utils.load_as(self._config, astype = 'physical')
		if not(bool(self._config.pid) ^ bool(self._config.eproc) ^ bool(self._config.ethrd)):
			if not(bool(self._config.pid) or bool(self._config.eproc) or bool(self._config.eproc)):
				debug.error("exactly *ONE* of the options --pid, --eproc or --ethrd must be specified (you have not specified _any_ of these options)")
			else:
				debug.error("exactly *ONE* of the options --pid, --eproc or --ethrd must be specified (you have used _multiple_ such options)")
		if bool(self._config.pid):
			# --pid
			eproc_matches = [ eproc for eproc in tasks.pslist(self.kernel_address_space) if eproc.UniqueProcessId == self._config.pid ]
			if len(eproc_matches) != 1:
				debug.error("--pid needs to take a *VALID* PID argument (could not find PID {0} in the process listing for this memory image)".format(self._config.pid))
			return [ eproc_matches[0] ]
		elif bool(self._config.eproc):
			# --eproc
			eproc = obj.Object("_EPROCESS", offset = self._config.eproc, vm = self.kernel_address_space)
			if eproc.is_valid():
				return [ eproc ]
			else:
				debug.error("--eproc needs to take a *VALID* _EPROCESS kernel address (could not find a valid _EPROCESS 0x{0:08X} in this memory image)".format(self._config.eproc))
		else:
			# --ethrd
			ethrd = obj.Object("_ETHREAD", offset = self._config.ethrd, vm = self.flat_address_space)
			if ethrd.is_valid():
				return [ ethrd ]
			else:
				debug.error("--ethrd needs to take a *VALID* _ETHREAD kernel address (could not find a valid _ETHREAD 0x{0:08X} in this memory image)".format(self._config.ethrd))

	def render_text(self, outfd, data):
		if bool(self._config.ethrd):
			for ethrd in data:
				eproc = ethrd.ThreadsProcess
				self.process_address_space = eproc.get_process_address_space()
				self.carve_thread(outfd, eproc, ethrd)
		else:
			for eproc in data:
				self.process_address_space = eproc.get_process_address_space()
				self.carve_process_threads(outfd, eproc)

	highlight_colour_cursor = "\x1b[1;34;1m"
	highlight_colour_frame = "\x1b[1;31;1m"
	highlight_colour_end = "\x1b[0m"
    
	colour_stack = [highlight_colour_end]

	def get_stack_frames(self, start_ebp, stack_base, stack_limit, start_eip=None):
		def stack_frame_iterator_up():
			# Perform a linear search looking for potential (old) EBP chain values in remnants of old stack frames
			ebp = start_ebp
			ebp_ptr = start_ebp - 4
			while stack_limit < ebp_ptr and ebp_ptr <= stack_base:
				# FIXME: check the alignment of stack frames (might be able to decrement with larger values?)
				if not self.process_address_space.is_valid_address(ebp_ptr):
					ebp_ptr -= 1
				else:
					ebp_value = self.flat_address_space.read_long(self.process_address_space.vtop(ebp_ptr))
					if ebp_value == ebp:
						ebp = ebp_ptr
						eip = self.flat_address_space.read_long(self.process_address_space.vtop(ebp_ptr+4))
						yield { 'eip':eip, 'ebp':ebp }
						ebp_ptr -= 4
					else:
						ebp_ptr -= 1
		def stack_frame_iterator_down():
			# Follow the EBP chain downloads and so locate stack frames
			if start_eip != None:
				yield { 'eip':start_eip, 'ebp':start_ebp }
			ebp = start_ebp
			while stack_base >= ebp and ebp > stack_limit:
				if not self.process_address_space.is_valid_address(ebp):
					return
				eip = self.flat_address_space.read_long(self.process_address_space.vtop(ebp+4))
				ebp = self.flat_address_space.read_long(self.process_address_space.vtop(ebp))
				if ebp == 0x0:
					return
				yield { 'eip':eip, 'ebp':ebp }
		old_stack_frames = [ frame for frame in stack_frame_iterator_up() ]
		old_stack_frames.reverse()
		current_stack_frames = [ frame for frame in stack_frame_iterator_down() ]
		if current_stack_frames != []:
			current_stack_frames[0]['highlight'] = True
		return old_stack_frames + current_stack_frames

	def add_vadentry(self, addr, vad_addr, storage):
		StartingVpn = obj.Object('_MMVAD_LONG', offset = vad_addr, vm = self.process_address_space).StartingVpn
		StartingVpn = StartingVpn << 12
		EndingVpn = obj.Object('_MMVAD_LONG', offset = vad_addr, vm = self.process_address_space).EndingVpn
		EndingVpn = ((EndingVpn+1) << 12) - 1
		if StartingVpn <= addr and addr <= EndingVpn:
			storage.append(vad_addr)

	def disasm(self, outfd, addr, size, backwards=False, highlight=None):
		if backwards:
			size = (size/2)+1
			addr = addr - size + 1
		# TODO: add in code so we can correctly disassemble code backwards!
		if addr < 0:
			return
		buf = self.process_address_space.read(addr, size)
		offset = 0
		while offset < size:
			if self.process_address_space.is_valid_address(addr+offset):
				i = pydasm.get_instruction(buf[offset:], pydasm.MODE_32)
				if not i: 
					if addr+offset == highlight:
						outfd.write("{0} => 0x{1:08X}{2}: ??\n".format(highlight_color_cursor, addr+offset, "".join(self.colour_stack)))
					else:
						outfd.write("    0x{0:08X}: ??\n".format(addr+offset))
					offset += 1 
				else:
					if addr+offset == highlight:
						outfd.write("{0} => 0x{1:08X}{2}: {3}\n".format(self.highlight_colour_cursor, addr+offset, "".join(self.colour_stack), pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, 0)))
					else:
						outfd.write("    0x{0:08X}: {1}\n".format(addr+offset, pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, 0)))
					offset += i.length
			else:
				if addr+offset == highlight:
					outfd.write("{0} => 0x{1:08X}{2}: unreadable\n".format(self.highlight_colour_cursor, addr+offset, "".join(self.colour_stack)))
				else:
					outfd.write("    0x{0:08X}: unreadable\n".format(addr+offset))
				offset += 4

	def print_vadinfo(self, outfd, vadroot, addr, win32addr):
		# FIXME: what are we doing here?
		vad_nodes = []
		for vad in vadroot.traverse():
			self.add_vadentry(addr, vad.v(), vad_nodes)
		win32_vad_nodes = []
		for vad in vadroot.traverse():
			self.add_vadentry(win32addr, vad.v(), win32_vad_nodes)
		if win32addr != 0 and win32addr != None and win32_vad_nodes == [] and vad_nodes == []:
			outfd.write("  Start Address: 0x{0:08X}\n".format(addr))
			outfd.write("  Win32 Start Address: 0x{0:08X}\n".format(win32addr))
		elif win32_vad_nodes != []:
			outfd.write("  Start Address: 0x{0:08X}\n".format(addr))
			outfd.write("  Win32 Start Address[*]: {0}0x{1:08X}{2}\n".format(self.highlight_colour_cursor, win32addr, "".join(self.colour_stack)))
			self.disasm(outfd, win32addr, 0x20, highlight=win32addr)
		else:
			outfd.write("  Start Address[*]: {0}0x{1:08X}{2}\n".format(self.highlight_colour_cursor, addr, "".join(self.colour_stack)))
			outfd.write("  Win32 Start Address: 0x{0:08X}\n".format(win32addr))
			self.disasm(outfd, addr, 0x20, highlight=addr)

	def dump_stack_frame(self, outfd, address, length=0x80, width=16, title="Frame Dump", highlight=None, stack_type="user"):
		if stack_type == "kernel":
			address_space = self.kernel_address_space
		else:
			address_space = self.process_address_space
		outfd.write("  {0}:\n".format(title))
		if length % 4 != 0:
			length = (length+4) - (length%4)
		outfd.write("               +0 +1 +2 +3 +4 +5 +6 +7 +8 +9 +A +B +C +D +E +F\n")
		FILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])
		N=0
		while N < length:
			data = ' '.join([ "{0:02X}".format(ord(x)) if x else '??' for x in [ address_space.read(address+N+i, 1) if address_space.is_valid_address(address+N+i) else None for i in range(0, width) ] ])
			hexa = ''.join([ x.translate(FILTER) if x else '.' for x in [ address_space.read(address+N+i, 1) if address_space.is_valid_address(address+N+i) else None for i in range(0, width) ] ])
			if highlight == address+N:
				outfd.write("{0} => 0x{1:08X}{2} {3:{width}} {4}\n".format(self.highlight_colour_cursor, address+N, "".join(self.colour_stack), data, hexa, width=width*3))
			else:
				outfd.write("    0x{0:08X} {1:{width}} {2}\n".format(address+N, data, hexa, width=width*3))
			N += width
		outfd.write("\n")

	def read_bitmap(self, bitmap, num):
		return (bitmap >> num) & 1 == 1

	def get_kthread_state(self, state):
		try:
			return ["Initialized", "Ready", "Running", "Standby", "Terminated", "Waiting", "Transition", "DeferredReady", "GateWait"][state]
		except:
			return "0x{0:08X} is an unknown thread state!".format(state)

	def unwind_stack(self, outfd, stack_frames, stack_type="user"):
		if stack_frames == []:
			return
		for frame in stack_frames:
			if 'highlight' in frame:
				outfd.write(self.highlight_colour_frame)
				self.colour_stack.append(self.highlight_colour_frame)
			outfd.write("  EIP: {0}0x{1:08X}{2}\n".format(self.highlight_colour_cursor, frame['eip'], "".join(self.colour_stack)))
			outfd.write("  EBP: {0}0x{1:08X}{2}\n".format(self.highlight_colour_cursor, frame['ebp'], "".join(self.colour_stack)))
			if frame['ebp'] >= 0x80:
				self.dump_stack_frame(outfd, frame['ebp']-0x40, 0x8d, highlight=frame['ebp'], stack_type=stack_type)
			if frame['eip'] > 0x20:
				outfd.write("  Calling Code Dissassembly:\n")
				self.disasm(outfd, frame['eip'], 0x40, backwards=True, highlight=frame['eip'])
			if 'highlight' in frame:
				self.colour_stack.pop()
				outfd.write("\n".join(self.colour_stack))
			outfd.write("-"*5)
			outfd.write("\n")

	def dump_trap_frame(self, outfd, trap_frame, title="User"):
		outfd.write("\n")
		outfd.write("  {0} Mode Registers:\n".format(title))
		for reg, data_reg in [('Eip', 'Eip'), ('Esp', 'HardwareEsp'), ('Ebp', 'Ebp'), ('Err', 'ErrCode')]:
			outfd.write("    {0}: 0x{1:08X}".format(reg, eval("trap_frame.{0}".format(data_reg))))
		outfd.write("\n")
		for reg in ['Eax', 'Ebx', 'Ecx', 'Edx']:
			outfd.write("    {0}: 0x{1:08X}".format(reg, eval("trap_frame.{0}".format(reg))))
		outfd.write("\n")
		for reg in ['Esi', 'Edi']:
			outfd.write("    {0}: 0x{1:08X}".format(reg, eval("trap_frame.{0}".format(reg))))
		outfd.write("\n")
		for reg, data_reg in [('CS', 'SegCs'), ('SS', 'HardwareSegSs'), ('DS', 'SegDs'), ('ES', 'SegEs')]:
			outfd.write("    {0}:  0x{1:08X}".format(reg, eval("trap_frame.{0}".format(data_reg))))
		outfd.write("\n")
		for reg, data_reg in [('GS: ', 'SegGs'), ('EFlags:', 'EFlags')]:
			outfd.write("    {0} 0x{1:08X}".format(reg, eval("trap_frame.{0}".format(data_reg))))
		outfd.write("\n")
		for reg in ['Dr0', 'Dr1', 'Dr2', 'Dr3']:
			outfd.write("    {0}: 0x{1:08X}".format(reg, eval("trap_frame.{0}".format(reg))))
		outfd.write("\n")
		for reg in ['Dr6', 'Dr7']:
			outfd.write("    {0}: 0x{1:08X}".format(reg, eval("trap_frame.{0}".format(reg))))
		outfd.write("\n")
		return { 'eip':trap_frame.Eip, 'ebp':trap_frame.Ebp }
		
	# Copied from the Threads class in malware.py
	def get_image_name(self, proc_offset):
		"""Safely read a process's name, assuming it could be invalid"""
		data = self.kernel_address_space.zread(proc_offset + self.kernel_address_space.profile.get_obj_offset("_EPROCESS", "ImageFileName"), 16)
		if data:
			if data.find("\x00") != -1:
				data = data[:data.find("\x00")]
			return repr(data)
		return ""

	def carve_thread(self, outfd, eproc, ethread):
		outfd.write("*"*20)
		outfd.write("\n")
		outfd.write("Process ID: {0} [_EPROCESS @ 0x{1:08X}; {2}]\n".format(ethread.Cid.UniqueProcess, eproc.v(), self.get_image_name(eproc.v())))
		if eproc.v() != ethread.Tcb.ApcState.Process.v():
			outfd.write("  Attached to _EPROCESS: 0x{0:08X}\n".format(ethread.Tcb.ApcState.Process))
		outfd.write("Thread ID: {0} [_ETHREAD @ 0x{1:08X}]\n".format(ethread.Cid.UniqueThread, ethread.v()))
		outfd.write("  Created: {0}\n".format(ethread.CreateTime or "-"))
		outfd.write("  Exited: {0}\n".format(ethread.ExitTime or "-"))
		outfd.write("  Kernel Time: {0}\n".format(ethread.Tcb.KernelTime))
		outfd.write("  User Time: {0}\n".format(ethread.Tcb.UserTime))
		outfd.write("  State: {0}\n".format(self.get_kthread_state(ethread.Tcb.State)))
		outfd.write("  TEB: 0x{0:08X}\n".format(ethread.Tcb.Teb))
		if self.read_bitmap(ethread.CrossThreadFlags, 0):
			outfd.write("  Terminated thread\n")
		if self.read_bitmap(ethread.CrossThreadFlags, 1):
			outfd.write("  Dead thread\n")
		if self.read_bitmap(ethread.CrossThreadFlags, 2):
			outfd.write("  Hide thread from debugger\n")
		if self.read_bitmap(ethread.CrossThreadFlags, 4):
			outfd.write("  System thread\n")
		self.print_vadinfo(outfd, eproc.VadRoot, ethread.StartAddress.v(), ethread.Win32StartAddress.v())
		trap_frame = obj.Object('_KTRAP_FRAME', offset = ethread.Tcb.TrapFrame.v(), vm = self.kernel_address_space)
		if trap_frame.is_valid():
			top_frame = self.dump_trap_frame(outfd, trap_frame)
		# FIXME: is this correct?
		esp = trap_frame.HardwareEsp.v() if trap_frame.is_valid() else ethread.Tcb.KernelStack.v()
		if esp >= 0x80000000:
			outfd.write("\n  Currently Using the Kernel Stack\n\n")
		else:
			outfd.write("\n  Currently Using the User Stack\n\n")
		# FIXME: what do the following do?
		kstack_base = ethread.Tcb.InitialStack.v()
		kstack_limit = ethread.Tcb.StackLimit.v()
		outfd.write("  Kernel Stack\n")
		outfd.write("    Base: 0x{0:08X}\n".format(kstack_base))
		outfd.write("    Limit: 0x{0:08X}\n".format(kstack_limit))
		if self.kernel_address_space.is_valid_address(ethread.Tcb.KernelStack.v()):
			outfd.write("Kernel Stack Unwind ==>\n")
			self.unwind_stack(outfd, self.get_stack_frames(ethread.Tcb.KernelStack.v(), kstack_base, kstack_limit), stack_type="kernel")
			outfd.write("<== End Kernel Stack Unwind\n")
			outfd.write("\n")
		#outfd.write("\n  Current Esp: {0}0x{1:08X}{2}\n".format(self.highlight_colour_cursor, esp, "".join(self.colour_stack)))
		#self.dump_stack_frame(outfd, esp-0x40, 0x8d, title="Current Esp Dump", highlight=esp, stack_type="")
		teb = obj.Object('_TEB', offset = ethread.Tcb.Teb.v(), vm = self.process_address_space)
		if teb.is_valid():
			ustack_base = teb.NtTib.StackBase.v()
			ustack_limit = teb.NtTib.StackLimit.v()
			outfd.write("  User Stack\n")
			outfd.write("    Base: 0x{0:08X}\n".format(ustack_base))
			outfd.write("    Limit: 0x{0:08X}\n".format(ustack_limit))
			if trap_frame.is_valid():
				outfd.write("User Stack Unwind ==>\n")
				self.unwind_stack(outfd, self.get_stack_frames(top_frame['ebp'], ustack_base, ustack_limit, top_frame['eip']), stack_type="user")
				outfd.write("<== End User Stack Unwind\n")
				outfd.write("\n")
			else:
				outfd.write("User Trap Frame is Invalid!\n")
		else:
			outfd.write("  TEB has been paged out!\n")
		outfd.write("End Process ID: {0}\n".format(ethread.Cid.UniqueProcess.v()))
		outfd.write("End Thread ID: {0}\n".format(ethread.Cid.UniqueThread.v()))
		outfd.write("*"*20)
		outfd.write("\n")

	def carve_process_threads(self, outfd, eproc):
		outfd.write("****************\n")
		outfd.write("* User Threads *\n")
		outfd.write("****************\n")
		[ self.carve_thread(outfd, eproc, ethread) for ethread in eproc.ThreadListHead.list_of_type("_ETHREAD", "ThreadListEntry") ]
		outfd.write("***************\n")
		outfd.write("* GUI Threads *\n")
		outfd.write("***************\n")
		# Windows GUI threads are only visible within the processes address space (the System process, most likely, has no access!)
		[ self.carve_thread(outfd, eproc, ethread.Tcb.Win32Thread.dereference_as("_W32THREAD").pEThread) for ethread in eproc.ThreadListHead.list_of_type('_ETHREAD', 'ThreadListEntry') if ethread.Tcb.Win32Thread.is_valid() and ethread.Tcb.Win32Thread.v() >= 0x80000000 ]
