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

_1752 = [Object('_ETHREAD', offset, self.flat_address_space, profile=self.eproc.profile) for offset in [0x01e6a790, 0x01ec5b88, 0x01ed2ab8, 0x02258b88, 0x02281bc0, 0x0228eda8, 0x02322020, 0x02472020 ]]

_888 = [Object('_ETHREAD', offset, self.flat_address_space, profile=self.eproc.profile) for offset in [0x01e67170, 0x01e6b308, 0x01ed6da8, 0x0225a020, 0x0225b538, 0x02261da8, 0x02282020, 0x0240a238, 0x02534c90]]

_880 = [Object('_ETHREAD', offset, self.flat_address_space, profile=self.eproc.profile) for offset in [0x01ed4420, 0x01edd020, 0x01ee99f0, 0x01eeb020, 0x01ef04f0, 0x01f01020, 0x01f294a8, 0x01fc1888, 0x02042398, 0x020cb020, 0x020d1020, 0x0225a9f8, 0x0225ac70, 0x02260da8, 0x0228c820, 0x022bd830, 0x022c1020, 0x022c4020, 0x022c7020, 0x022cbb48, 0x022cc708, 0x02303ba0, 0x02406020, 0x02406498, 0x024659f8, 0x024665b8, 0x024e42e8, 0x02534020]]

_1244 = [Object('_ETHREAD', offset, self.flat_address_space, profile=self.eproc.profile) for offset in [0x01e95428, 0x01f2b020, 0x01f36020, 0x01fdc7c0, 0x01fe5358, 0x01ff6020, 0x0225bbe8, 0x0225cda8, 0x022bbb30, 0x022c1810, 0x022c6020, 0x022c6b30, 0x022c6da8, 0x022c83c8, 0x02309020, 0x0230a368, 0x02404648, 0x02416638, 0x02463020] ]

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
    else:
        print "  Start Address[*]: 0x%0.8x"%addr
        print "  Win32 Start Address: 0x%0.8x"%win32addr

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

def carvestack(ethread):
    print "Process ID: %d"%ethread.Cid.UniqueProcess.v()
    print "Thread ID: %d"%ethread.Cid.UniqueThread.v()
    if (ethread.CrossThreadFlags >> 0) & 1:
        print "  Terminated thread"
    if (ethread.CrossThreadFlags >> 1) & 1:
        print "  Dead thread"
    if (ethread.CrossThreadFlags >> 2) & 1:
        print "  Hide thread from debugger"
    if (ethread.CrossThreadFlags >> 4) & 1:
        print "  System thread"
    print_vadinfo(self.eproc.VadRoot.v(), ethread.StartAddress.v(), ethread.Win32StartAddress.v())
    trap_frame = Object('_KTRAP_FRAME', ethread.Tcb.TrapFrame.v(), self.process_address_space, profile=self.eproc.profile)
    if trap_frame.is_valid():
        print "  CPU Registers:"
        for reg in ['Eax', 'Ebx', 'Ecx', 'Edx', 'Edi', 'Esi']:
            print "    %s: 0x%0.8x"%(reg, eval("trap_frame.%s"%reg))
    teb = Object('_TEB', ethread.Tcb.Teb.v(), self.process_address_space, profile=self.eproc.profile)
    if teb.is_valid():
        print "  Stack"
        print "    Base: 0x%0.8x"%teb.NtTib.StackBase.v()
        print "    Limit: 0x%0.8x"%teb.NtTib.StackLimit.v()
    else:
        print "  TEB has been paged out!"
    stack_frames = get_stack_frames(ethread)
    if stack_frames == []:
        print "  Dump:"
        dump_stack_frame(teb.NtTib.StackLimit.v()-0x40, 0x8d)
    else:
        print "Stack Unwind ==>"
        for frame in stack_frames:
            print "  EIP: 0x%0.8x"%frame['eip']
            print "  EBP: 0x%0.8x"%frame['ebp']
            if frame['ebp'] >= 0x80:
                dump_stack_frame(frame['ebp']-0x40, 0x8d)
            if frame['eip'] > 0x20:
                print "  Calling Code Dissassembly:"
                disasm(frame['eip']-0x20, 0x21)
            print "-"*5
    # FIXME: w32thread code doesn't appear to work as expected!?
    w32thread = Object('_ETHREAD', ethread.Tcb.Win32Thread.v(), self.kernel_address_space, profile=self.eproc.profile)
    if w32thread.is_valid() and w32thread.offset >= 0x80000000:
        print "  GUI Process: %d"%w32thread.Cid.UniqueProcess.v()
        print "  GUI Thread: %d"%w32thread.Cid.UniqueThread.v()
    else:
        print "  no GUI thread"
    print "*"*20
        