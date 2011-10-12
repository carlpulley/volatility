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
import commands as exe
import os.path
import math
import struct
import hashlib
import volatility.utils as utils
import volatility.obj as obj
import volatility.win32.tasks as tasks
import volatility.debug as debug
import volatility.commands as commands
import volatility.plugins.filescan as filescan

class ExportException(Exception):
	"""General exception for handling warnings and errors during exporting of stacks"""
	pass

class ExportStack(filescan.FileScan):
	"""
	TODO:
	
	REFERENCES:
	[1] Russinovich, M., Solomon, D.A. & Ionescu, A., 2009. Windows Internals: 
	    Including Windows Server 2008 and Windows Vista, Fifth Edition (Pro 
	    Developer) 5th ed. Microsoft Press.
	[2] Information on mapping _FILE_OBJECT's to _EPROCESS (accessed 6/Oct/2011):
	    http://computer.forensikblog.de/en/2009/04/linking_file_objects_to_processes.html
	[3] OSR Online article: Finding File Contents in Memory (accessed 7/Oct/2011):
	    http://www.osronline.com/article.cfm?article=280
	[4] Extracting Event Logs or Other Memory Mapped Files from Memory Dumps by 
	    J. McCash (accessed 7/Oct/2011):
	    http://computer-forensics.sans.org/blog/2011/02/01/digital-forensics-extracting-event-logs-memory-mapped-files-memory-dumps
	[5] Physical Memory Forensics for Files and Cache by J. Butler and J. 
	    Murdock (accessed 8/Oct/2011):
	    https://media.blackhat.com/bh-us-11/Butler/BH_US_11_ButlerMurdock_Physical_Memory_Forensics-WP.pdf
	[6] CodeMachine article on Prototype PTEs (accessed 8/Oct/2011):
	    http://www.codemachine.com/article_protopte.html
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
		config.add_option("fill", default = 0, type = 'int', action = 'store', help = "Fill character (byte) for padding out missing pages")
		config.add_option("dir", short_option = 'D', type = 'str', action = 'store', help = "Directory in which to save exported files")
		config.add_option("pid", type = 'int', action = 'store', help = "Extract all associated _FILE_OBJECT's from a PID")
		config.add_option("eproc", type = 'int', action = 'store', help = "Extract all associated _FILE_OBJECT's from an _EPROCESS offset (kernel address)")
		config.add_option("fobj", type = 'int', action = 'store', help = "Extract a given _FILE_OBJECT offset (physical address)")
		config.add_option("pool", default = False, action = 'store_true', help = "Extract all _FILE_OBJECT's found by searching the pool")

	def calculate(self):
		self.kernel_address_space = utils.load_as(self._config)
		self.flat_address_space = utils.load_as(self._config, astype = 'physical')
		if not(bool(self._config.DIR)):
			debug.error("--dir needs to be present")
		if not(bool(self._config.pid) ^ bool(self._config.eproc) ^ bool(self._config.fobj) ^ bool(self._config.pool)):
			if not(bool(self._config.pid) or bool(self._config.eproc) or bool(self._config.fobj) or bool(self._config.pool)):
				debug.error("exactly *ONE* of the options --pid, --eproc, --fobj or --pool must be specified (you have not specified _any_ of these options)")
			else:
				debug.error("exactly *ONE* of the options --pid, --eproc, --fobj or --pool must be specified (you have used _multiple_ such options)")
		if bool(self._config.pid):
			# --pid
			eproc_matches = [ eproc for eproc in tasks.pslist(self.kernel_address_space) if eproc.UniqueProcessId == self._config.pid ]
			if len(eproc_matches) != 1:
				debug.error("--pid needs to take a *VALID* PID argument (could not find PID {0} in the process listing for this memory image)".format(self._config.pid))
			return self.dump_from_eproc(eproc_matches[0])
		elif bool(self._config.eproc):
			# --eproc
			return self.dump_from_eproc(obj.Object("_EPROCESS", offset = self._config.eproc, vm = self.kernel_address_space))
		elif bool(self._config.fobj):
			# --fobj
			try:
				return filter(None, [ self.dump_file_object(obj.Object("_FILE_OBJECT", offset = self._config.fobj, vm = self.flat_address_space)) ])
			except ExportException as exn:
				debug.error(exn)
		else:
			# --pool
			return self.dump_from_pool()

	def render_text(self, outfd, data):
		base_dir = os.path.abspath(self._config.dir)
		for file_data in data:
			for data_type, fobj_inst, file_name, file_size, extracted_file_data in file_data:
				# FIXME: fix this hacky way of creating directory structures
				file_name_path = re.sub(r'[\\:]', '/', base_dir + "/" + file_name)
				if not(os.path.exists(file_name_path)):
					exe.getoutput("mkdir -p {0}".format(re.escape(file_name_path)))
				outfd.write("#"*20)
				outfd.write("\nExporting {0} [_FILE_OBJECT @ 0x{1:08X}]:\n  {2}\n\n".format(data_type, fobj_inst.v(), file_name))
				if data_type == "_SHARED_CACHE_MAP":
					# _SHARED_CACHE_MAP processing
					self.dump_shared_pages(outfd, data, fobj_inst, file_name_path, file_size, extracted_file_data)
				elif data_type == "_CONTROL_AREA":
					# _CONTROL_AREA processing
					self.dump_control_pages(outfd, data, fobj_inst, file_name_path, extracted_file_data)
				self.reconstruct_file(outfd, fobj_inst, file_name_path)

	self.KB = 0x400
	self._1KB = self.KB
	self.MB = self._1KB**2
	self._1MB = self.MB
	self.GB = self._1KB**3
	self._1GB = self.GB

	def get_stack_frames(start_ebp, stack_base, stack_limit, start_eip=None):
	    def stack_frame_iterator_up():
	        ebp = start_ebp
	        ebp_ptr = start_ebp - 4
	        while stack_limit < ebp_ptr and ebp_ptr <= stack_base:
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

	def add_vadentry(addr, addr_space, types, vad_addr, level, storage):
	    StartingVpn = read_obj(addr_space, types, ['_MMVAD_LONG', 'StartingVpn'], vad_addr)  
	    StartingVpn = StartingVpn << 12
	    EndingVpn = read_obj(addr_space, types, ['_MMVAD_LONG', 'EndingVpn'], vad_addr)
	    EndingVpn = ((EndingVpn+1) << 12) - 1
	    if StartingVpn <= addr and addr <= EndingVpn:
	        storage.append(vad_addr)

	def disasm(addr, size, backwards=False, highlight=None):
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
	                    print "%s => 0x%0.8X%s: ??"%(highlight_color_cursor, addr+offset, "".join(colour_stack))
	                else:
	                    print "    0x%0.8X: ??"%(addr+offset)
	                offset += 1 
	            else:
	                if addr+offset == highlight:
	                    print "%s => 0x%0.8X%s: %s"%(highlight_colour_cursor, addr+offset, "".join(colour_stack), pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, 0))
	                else:
	                    print "    0x%0.8X: %s"%(addr+offset, pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, 0))
	                offset += i.length
	        else:
	            if addr+offset == highlight:
	                print "%s => 0x%0.8X%s: unreadable"%(highlight_colour_cursor, addr+offset, "".join(colour_stack))
	            else:
	                print "    0x%0.8X: unreadable"%(addr+offset)
	            offset += 4

	def print_vadinfo(vadroot, addr, win32addr):
	    vad_nodes = []
	    traverse_vad(None, self.eproc.vm, self.types, vadroot, lambda addr_space, types, vad_addr, level, storage: add_vadentry(addr, addr_space, types, vad_addr, level, storage), None, None, 0, vad_nodes)
	    win32_vad_nodes = []
	    traverse_vad(None, self.eproc.vm, self.types, vadroot, lambda addr_space, types, vad_addr, level, storage: add_vadentry(win32addr, addr_space, types, vad_addr, level, storage), None, None, 0, win32_vad_nodes)
	    if win32addr != 0 and win32_vad_nodes == [] and vad_nodes == []:
	        print "  Start Address: 0x%0.8x"%addr
	        print "  Win32 Start Address: 0x%0.8x"%win32addr     
	    elif win32_vad_nodes != []:
	        print "  Start Address: 0x%0.8x"%addr
	        print "  Win32 Start Address[*]: %s0x%0.8x%s"%(highlight_colour_cursor, win32addr, "".join(colour_stack))
	        disasm(win32addr, 0x20, highlight=win32addr)
	    else:
	        print "  Start Address[*]: %s0x%0.8x%s"%(highlight_colour_cursor, addr, "".join(colour_stack))
	        print "  Win32 Start Address: 0x%0.8x"%win32addr
	        disasm(addr, 0x20, highlight=addr)

	def dump_stack_frame(address, length=0x80, width=16, title="Frame Dump", highlight=None):
	    print "  %s:"%title
	    if length % 4 != 0:
	        length = (length+4) - (length%4)
	    print "               +0 +1 +2 +3 +4 +5 +6 +7 +8 +9 +A +B +C +D +E +F"
	    FILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])
	    N=0
	    while N < length:
	        data = ' '.join([ "%02X"%ord(x) if x else '??' for x in [ self.process_address_space.read(address+N+i, 1) for i in range(0, width) ] ])
	        hexa = ''.join([ x.translate(FILTER) if x else '.' for x in [ self.process_address_space.read(address+N+i, 1) for i in range(0, width) ] ])
	        if highlight == address+N:
	            print "%s => 0x%08X%s %-*s %s"%(highlight_colour_cursor, address+N, "".join(colour_stack), width*3, data, hexa)
	        else:
	            print "    0x%08X %-*s %s"%(address+N, width*3, data, hexa)
	        N += width
	    print

	def read_bitmap(bitmap, num):
	    return (bitmap >> num) & 1 == 1

	def get_kthread_state(state):
	    try:
	        return ["Initialized", "Ready", "Running", "Standby", "Terminated", "Waiting", "Transition", "DeferredReady", "GateWait"][state]
	    except:
	        return "%d is an unknown thread state!"%state

	def unwind_stack(stack_frames):
	    if stack_frames == []:
	        return
	    for frame in stack_frames:
	        if 'highlight' in frame:
	            print highlight_colour_frame
	            colour_stack.append(highlight_colour_frame)
	        print "  EIP: %s0x%0.8x%s"%(highlight_colour_cursor, frame['eip'], "".join(colour_stack))
	        print "  EBP: %s0x%0.8x%s"%(highlight_colour_cursor, frame['ebp'], "".join(colour_stack))
	        if frame['ebp'] >= 0x80:
	            dump_stack_frame(frame['ebp']-0x40, 0x8d, highlight=frame['ebp'])
	        if frame['eip'] > 0x20:
	            print "  Calling Code Dissassembly:"
	            disasm(frame['eip'], 0x40, backwards=True, highlight=frame['eip'])
	        if 'highlight' in frame:
	            colour_stack.pop()
	            print "".join(colour_stack)
	        print "-"*5

	def dump_trap_frame(trap_frame, title="User"):
	    print
	    print "  %s Mode Registers:"%title
	    for reg in ['Eip', 'Ebp', 'Eax', 'Ebx', 'Ecx', 'Edx', 'Edi', 'Esi']:
	        print "    %s: 0x%0.8x"%(reg, eval("trap_frame.%s"%reg))
	    return { 'eip':trap_frame.Eip, 'ebp':trap_frame.Ebp }

	def carve_thread(ethread):
	    print "*"*20
	    print "Process ID: %d"%ethread.Cid.UniqueProcess.v()
	    print "Thread ID: %d"%ethread.Cid.UniqueThread.v()
	    print "  Kernel Time: %d"%ethread.Tcb.KernelTime
	    print "  User Time: %d"%ethread.Tcb.UserTime
	    print "  State: %s"%get_kthread_state(ethread.Tcb.State)
	    if read_bitmap(ethread.CrossThreadFlags, 0):
	        print "  Terminated thread"
	    if read_bitmap(ethread.CrossThreadFlags, 1):
	        print "  Dead thread"
	    if read_bitmap(ethread.CrossThreadFlags, 2):
	        print "  Hide thread from debugger"
	    if read_bitmap(ethread.CrossThreadFlags, 4):
	        print "  System thread"
	    print_vadinfo(self.eproc.VadRoot.v(), ethread.StartAddress.v(), ethread.Win32StartAddress.v())
	    trap_frame = Object('_KTRAP_FRAME', ethread.Tcb.TrapFrame.v(), self.process_address_space, profile=self.eproc.profile)
	    if trap_frame.is_valid():
	        top_frame = dump_trap_frame(trap_frame)
	    esp = ethread.Tcb.KernelStack.v()
	    if esp >= 0x80000000:
	        print "  Current Stack [Kernel]"
	    else:
	        print "  Current Stack [User]"
	    stack_base = ethread.Tcb.InitialStack.v()
	    stack_limit = ethread.Tcb.StackLimit.v()
	    print "    Base: 0x%0.8x"%stack_base
	    print "    Limit: 0x%0.8x"%stack_limit
	    print "    Current Esp: %s0x%0.8x%s"%(highlight_colour_cursor, esp, "".join(colour_stack))
	    dump_stack_frame(esp-0x40, 0x8d, title="Current Esp Dump", highlight=esp)
	    teb = Object('_TEB', ethread.Tcb.Teb.v(), self.process_address_space, profile=self.eproc.profile)
	    if teb.is_valid():
	        stack_base = teb.NtTib.StackBase.v()
	        stack_limit = teb.NtTib.StackLimit.v()
	        print "  User Stack"
	        print "    Base: 0x%0.8x"%stack_base
	        print "    Limit: 0x%0.8x"%stack_limit
	        if trap_frame.is_valid():
	            print "User Stack Unwind ==>"
	            unwind_stack(get_stack_frames(top_frame['ebp'], stack_base, stack_limit, top_frame['eip']))
	            print "<== End User Stack Unwind"
	            print
	        else:
	            print "User Trap Frame is Invalid!"
	    else:
	        print "  TEB has been paged out!"
	    print "End Process ID: %d"%ethread.Cid.UniqueProcess.v()
	    print "End Thread ID: %d"%ethread.Cid.UniqueThread.v()
	    print "*"*20

	def carve_process_threads():
	    print "****************"
	    print "* User Threads *"
	    print "****************"
	    [ carve_thread(ethread) for ethread in list_entry(self.eproc.ThreadListHead.v(), '_ETHREAD', fieldname='ThreadListEntry') ]
	    print "***************"
	    print "* GUI Threads *"
	    print "***************"
	    [ carve_thread(ethread.Tcb.Win32Thread) for ethread in list_entry(self.eproc.ThreadListHead.v(), '_ETHREAD', fieldname='ThreadListEntry') if ethread.Tcb.Win32Thread.is_valid() and ethread.Tcb.Win32Thread.offset >= 0x80000000 ]
