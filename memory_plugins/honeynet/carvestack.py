import re
import commands
import os.path
import pydasm
import fileobjscan, malfind2
from forensics.win32.vad import traverse_vad, vad_info

KB = 0x400
_1KB = KB
MB = _1KB**2
_1MB = MB
GB = _1KB**3
_1GB = GB

self.types.update(fileobjscan.extra_types)
self.flat_address_space = find_addr_space(FileAddressSpace(self.opts.filename), self.types)
self.search_address_space = find_addr_space(self.flat_address_space, self.types)
self.sysdtb = get_dtb(self.search_address_space, self.types)
self.kernel_address_space = load_pae_address_space(self.opts.filename, self.sysdtb)

def get_stack_frames(ethread):
    def stack_frame_iterator(ethread):
        teb = Object('_TEB', ethread.Tcb.Teb.v(), self.process_address_space, profile=self.eproc.profile)
        stack_base = teb.NtTib.StackBase.v()
        stack_limit = teb.NtTib.StackLimit.v()
        trap_frame = Object('_KTRAP_FRAME', ethread.Tcb.TrapFrame.v(), self.process_address_space, profile=self.eproc.profile)
        if not trap_frame.is_valid():
            return
        ebp = trap_frame.Ebp
        eip = trap_frame.Eip
        yield { 'eip':eip, 'ebp':ebp }
        while stack_base >= ebp and ebp > stack_limit:
            eip = self.flat_address_space.read_long(trap_frame.vm.vtop(ebp+4))
            ebp = self.flat_address_space.read_long(trap_frame.vm.vtop(ebp))
            if ebp == 0x0:
                return
            yield { 'eip':eip, 'ebp':ebp }
    return [ frame for frame in stack_frame_iterator(ethread) ]

def add_vadentry(addr, addr_space, types, vad_addr, level, storage):
    StartingVpn = read_obj(addr_space, types, ['_MMVAD_LONG', 'StartingVpn'], vad_addr)  
    StartingVpn = StartingVpn << 12
    EndingVpn = read_obj(addr_space, types, ['_MMVAD_LONG', 'EndingVpn'], vad_addr)
    EndingVpn = ((EndingVpn+1) << 12) - 1
    if StartingVpn <= addr and addr <= EndingVpn:
        storage.append(vad_addr)

def disasm(addr, size):
    if addr < 0:
        return
    buf = self.process_address_space.read(addr, size)
    offset = 0
    while offset < size:
        if self.process_address_space.is_valid_address(addr+offset):
            i = pydasm.get_instruction(buf[offset:], pydasm.MODE_32)
            if not i: 
                print "    0x%0.8X: ??"%(addr+offset)
                offset += 1 
            else:
                print "    0x%0.8X: %s"%(addr+offset, pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, 0))
                offset += i.length
        else:
            print "    0x%0.8X: unreadable"%(addr+offset)
            offset += 4

def print_vadinfo(vadroot, addr, win32addr):
    vad_nodes = []
    traverse_vad(None, self.eproc.vm, self.types, vadroot, lambda addr_space, types, vad_addr, level, storage: add_vadentry(addr, addr_space, types, vad_addr, level, storage), None, None, 0, vad_nodes)
    win32_vad_nodes = []
    traverse_vad(None, self.eproc.vm, self.types, vadroot, lambda addr_space, types, vad_addr, level, storage: add_vadentry(win32addr, addr_space, types, vad_addr, level, storage), None, None, 0, win32_vad_nodes)
    if win32_vad_nodes == [] and vad_nodes == []:
        print "  Start Address: 0x%0.8x"%addr
        print "  Win32 Start Address: 0x%0.8x"%win32addr     
    elif win32_vad_nodes != []:
        print "  Start Address: 0x%0.8x"%addr
        print "  Win32 Start Address[*]: 0x%0.8x"%win32addr
        disasm(win32addr, 0x20)
    else:
        print "  Start Address[*]: 0x%0.8x"%addr
        print "  Win32 Start Address: 0x%0.8x"%win32addr
        disasm(addr, 0x20)

def dump_stack_frame(address, length=0x80, width=16):
    print "  Frame Dump:"
    if length % 4 != 0:
        length = (length+4) - (length%4)
    print "               00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F"
    FILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])
    N=0
    while N < length:
        data = ' '.join([ "%02X"%ord(x) if x else '??' for x in [ self.process_address_space.read(address+N+i, 1) for i in range(0, width) ] ])
        hexa = ''.join([ x.translate(FILTER) if x else '.' for x in [ self.process_address_space.read(address+N+i, 1) for i in range(0, width) ] ])
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

def carve_thread(ethread):
    print "Process ID: %d"%ethread.Cid.UniqueProcess.v()
    print "Thread ID: %d"%ethread.Cid.UniqueThread.v()
    if read_bitmap(ethread.CrossThreadFlags, 0):
        print "  Terminated thread"
    if read_bitmap(ethread.CrossThreadFlags, 1):
        print "  Dead thread"
    if read_bitmap(ethread.CrossThreadFlags, 2):
        print "  Hide thread from debugger"
    if read_bitmap(ethread.CrossThreadFlags, 4):
        print "  System thread"
    print_vadinfo(self.eproc.VadRoot.v(), ethread.StartAddress.v(), ethread.Win32StartAddress.v())
    print "  State: %s"%get_kthread_state(ethread.Tcb.State)
    trap_frame = Object('_KTRAP_FRAME', ethread.Tcb.TrapFrame.v(), self.process_address_space, profile=self.eproc.profile)
    if trap_frame.is_valid():
        print "  User Mode Registers:"
        for reg in ['Eip', 'Ebp', 'Eax', 'Ebx', 'Ecx', 'Edx', 'Edi', 'Esi']:
            print "    %s: 0x%0.8x"%(reg, eval("trap_frame.%s"%reg))
    teb = Object('_TEB', ethread.Tcb.Teb.v(), self.process_address_space, profile=self.eproc.profile)
    if teb.is_valid():
        print "  User Stack"
        print "    Base: 0x%0.8x"%teb.NtTib.StackBase.v()
        print "    Limit: 0x%0.8x"%teb.NtTib.StackLimit.v()
    else:
        print "  TEB has been paged out!"
    stack_frames = get_stack_frames(ethread)
    if stack_frames == []:
        if teb.is_valid():
            print "  Dump:"
            dump_stack_frame(teb.NtTib.StackLimit.v()-0x40, 0x8d)
    else:
        print "User Stack Unwind ==>"
        for frame in stack_frames:
            if stack_frames.index(frame) > 0:
                print "  EIP: 0x%0.8x"%frame['eip']
                print "  EBP: 0x%0.8x"%frame['ebp']
            if frame['ebp'] >= 0x80:
                dump_stack_frame(frame['ebp']-0x40, 0x8d)
            if frame['eip'] > 0x20:
                print "  Calling Code Dissassembly:"
                disasm(frame['eip']-0x20, 0x21)
            print "-"*5
    print "*"*20

def carve_process_threads():
    print "****************"
    print "* User Threads *"
    print "****************"
    [ carve_thread(ethread) for ethread in list_entry(self.eproc.ThreadListHead.v(), '_ETHREAD', fieldname='ThreadListEntry') ]
