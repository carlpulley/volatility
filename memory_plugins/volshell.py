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

"""
@author:       AAron Walters and Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com,bdolangavitt@wesleyan.edu
@organization: Volatile Systems
"""

from forensics.object2 import *
from forensics.win32.tasks import * 
from vutils import *
import sys

class volshell(forensics.commands.command):

    # Declare meta information associated with this plugin
    
    meta_info = forensics.commands.command.meta_info 
    meta_info['author'] = 'Brendan Dolan-Gavitt'
    meta_info['copyright'] = 'Copyright (c) 2007,2008 Brendan Dolan-Gavitt'
    meta_info['contact'] = 'bdolangavitt@wesleyan.edu'
    meta_info['license'] = 'GNU General Public License 2.0 or later'
    meta_info['url'] = 'http://moyix.blogspot.com/'
    meta_info['os'] = 'WIN_32_XP_SP2'
    meta_info['version'] = '1.0'

    def help(self):
        return  "Shell in the memory image"
    
    def parser(self):
        forensics.commands.command.parser(self)
        self.op.add_option('-o', '--offset',
                  help='Get shell in the context of this EPROCESS (hex offset)',
                  action='store', type='string', dest='offset')
        self.op.add_option('-n', '--name',
                  help='Get shell in the context of process with this name',
                  action='store', type='string', dest='imname')
        self.op.add_option('-p', '--pid',
                  help='Get shell in the context of process with this PID',
                  action='store', type='int', dest='pid')

    def ps(self, procs=None):
        if not procs: procs = self.pslist
        print "%-16s %-6s %-6s %-8s" % ("Name", "PID", "PPID", "Offset")
        for p in procs:
            eproc = Object("_EPROCESS", p, self.process_address_space,
                           profile=Profile())
            print "%-16s %-6d %-6d %#08x" % (eproc.ImageFileName,
                                            eproc.UniqueProcessId.v(),
                                            eproc.InheritedFromUniqueProcessId.v(),
                                            eproc.offset)

    def set_context(self, offset=None, pid=None, name=None):
        if pid is not None:
            offsets = []
            for p in self.pslist:
                if process_pid(self.addr_space, self.types, p) == pid:
                    offsets.append(p)
            if not offsets:
                print "Unable to find process matching pid %d" % pid
                return
            elif len(offsets) > 1:
                print "Multiple processes match %d, please specify by offset" % pid
                print "Matching processes:"
                self.ps(offsets)
                return
            else: offset = offsets[0]
        elif name is not None:
            offsets = []
            for p in self.pslist:
                if process_imagename(self.addr_space, self.types, p) == name:
                    offsets.append(p)
            if not offsets:
                print "Unable to find process matching name %s" % name 
                return
            elif len(offsets) > 1:
                print "Multiple processes match name %s, please specify by PID or offset" % name
                print "Matching processes:"
                self.ps(offsets)
                return
            else: offset = offsets[0]
        elif offset is None:
            print "Must provide one of: offset, name, or pid as a argument."
            return

        self.dtb = process_dtb(self.addr_space, self.types, offset)
        self.process_address_space = create_addr_space(self.addr_space, self.dtb)
        self.image_name = process_imagename(self.process_address_space, self.types, offset)
        self.image_pid = process_pid(self.process_address_space, self.types, offset)
        self.image_ppid = process_inherited_from(self.process_address_space, self.types, offset)
        self.image_offset = offset
        self.eproc = Object("_EPROCESS", self.image_offset,
                            self.process_address_space, profile=Profile())

        print "Current context: process %s, pid=%d, ppid=%d DTB=%#x" % (self.image_name,
            self.image_pid, self.image_ppid, self.dtb)

    def execute(self):
        self.ctx = {}
        (self.addr_space, self.symtab, self.types) = load_and_identify_image(self.op, self.opts)
        self.pslist = process_list(self.addr_space, self.types, self.symtab)
        
        if self.opts.filename is None:
            self.op.error("volshell -f <filename:required> [options]")
        else:
            filename = self.opts.filename    

        try:
            flat_address_space = FileAddressSpace(filename)
        except:
            self.op.error("Unable to open image file %s" %(filename))
        
        flat_address_space = find_addr_space(flat_address_space, self.types)

        if not self.opts.offset is None:
            try:
                offset = int(self.opts.offset, 16)
            except:
                self.op.error("EPROCESS offset must be a hexadecimal number.")

            # Special case: physical EPROCESS offset
            self.dtb = process_dtb(flat_address_space, types, offset)
            self.process_address_space = create_addr_space(self.addr_space, self.dtb)

            if self.process_address_space is None:
                print "Error obtaining address space for offset %#08x" % (offset)
                return

            self.image_name = process_imagename(flat_address_space, self.types, offset)
            self.image_pid = process_pid(flat_address_space, self.types, offset)
            self.image_ppid = process_inherited_from(flat_address_space, self.types, offset)
            self.image_offset = offset
            print "Current context: process %s, pid=%d, ppid=%d DTB=%#x" % (self.image_name,
                self.image_pid, self.image_ppid, self.dtb)

        elif self.opts.pid is not None:
            self.set_context(pid=self.opts.pid)
        elif self.opts.imname is not None:
            self.set_context(name=self.opts.imname)
        else:
            # Just use the first process, whatever it is
            self.set_context(offset=self.pslist[0])

        # Functions inside the shell
        def cc(offset=None, pid=None, name=None):
            """Change current shell context.

            This function changes the current shell context to to the process
            specified. The process specification can be given as a virtual address
            (option: offset), PID (option: pid), or process name (option: name).

            If multiple processes match the given PID or name, you will be shown a
            list of matching processes, and will have to specify by offset.
            """
            self.set_context(offset=offset, pid=pid, name=name)

        def db(address, length=0x80, width=16):
            """Print bytes as canonical hexdump.
            
            This function prints bytes at the given virtual address as a canonical
            hexdump. The address will be translated in the current process context
            (see help on cc for information on how to change contexts).
            
            The length parameter (default: 0x80) specifies how many bytes to print,
            and the width parameter (default: 16) allows you to change how many
            bytes per line should be displayed.
            """
            if length % 4 != 0:
                length = (length+4) - (length%4)
            data = self.process_address_space.read(address,length)
            if not data:
                print "Memory unreadable at %08x" % address
                return

            FILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])
            N=0; result=''
            while data:
                s,data = data[:width],data[width:]
                hexa = ' '.join(["%02X"%ord(x) for x in s])
                s = s.translate(FILTER)
                result += "%08X   %-*s   %s\n" % (address+N, width*3, hexa, s)
                N+=width
            print result

        def dd(address, length=0x80):
            """Print dwords at address.

            This function prints the data at the given address, interpreted as
            a series of dwords (unsigned four-byte integers) in hexadecimal.
            The address will be translated in the current process context
            (see help on cc for information on how to change contexts).
            
            The optional length parameter (default: 0x80) controls how many bytes
            to display.
            """
            # round up to multiple of 4
            if length % 4 != 0:
                length = (length+4) - (length%4)
            data = self.process_address_space.read(address,length)
            if not data:
                print "Memory unreadable at %08x" % address
                return
            dwords = []
            for i in range(0,length,4):
                (dw,) = unpack("<L", data[i:i+4])
                dwords.append(dw)

            if len(dwords) % 4 == 0: lines = len(dwords) / 4
            else: lines = len(dwords) / 4 + 1
                
            for i in range(lines):
                ad = address + i*0x10
                lwords = dwords[i*4:i*4+4]
                print ("%08x  " % ad) + " ".join("%08x" % l for l in lwords)

        def ps():
            """Print a process listing.

            Prints a process listing with PID, PPID, image name, and offset.
            """
            self.ps()

        def list_entry(head, objname, offset=-1, fieldname=None, forward=True):
            """Traverse a _LIST_ENTRY.

            Traverses a _LIST_ENTRY starting at virtual address head made up of
            objects of type objname. The value of offset should be set to the
            offset of the _LIST_ENTRY within the desired object."""
            
            vm = self.process_address_space
            profile = self.eproc.profile
            seen = set()

            if fieldname:
                offset,typ = get_obj_offset(types, [objname,fieldname])
                if typ != "_LIST_ENTRY":
                    print ("WARN: given field is not a LIST_ENTRY, attempting to "
                           "continue anyway.")

            lst = Object("_LIST_ENTRY", head, vm, profile=profile)
            seen.add(lst)
            if not lst.is_valid(): return
            while True:
                if forward:
                    lst = lst.Flink
                else:
                    lst = lst.Blink
                
                if not lst.is_valid(): return
                
                if lst in seen: break
                else: seen.add(lst)

                obj = Object(objname, lst.offset - offset, vm, profile=profile)
                yield obj

        def dt(obj):
            """Describe an object or show type info.

            Show the names and values of a complex object (struct). If the name of a
            structure is passed, show the struct's members and their types."""

            if isinstance(obj,str):
                size = self.types[obj][0]
                membs = self.types[obj][1]
                membs = [ (get_obj_offset(self.types, [obj,m])[0],m,self.types[obj][1][m][1]) for m in membs ]
                membs.sort()
                print obj, "(%d bytes)" % size
                for o,m,t in membs:
                    print "%-6s: %-30s %s" % (hex(o),m,t)
            else:
                membs = obj.get_member_names()
                membs = [ (obj.get_member_offset(m,relative=True),m) for m in membs if m not in obj.extra_members ]
                membs.sort()
                print obj
                for o,m in membs:
                    val = getattr(obj,m)
                    if isinstance(val,list):
                        val = [ str(v) for v in val ]
                    print "%-6s: %-30s %s" % (hex(o),m,val)
                if obj.extra_members:
                    print "Calculated members:"
                    for m in obj.extra_members:
                        print "        %-30s %s" % (m,getattr(obj,m))

        shell_funcs = { 'cc': cc, 'dd': dd, 'db': db, 'ps': ps, 'dt': dt, 'list_entry': list_entry}
        def hh(cmd=None):
            """Get help on a command."""
            shell_funcs['hh'] = hh
            import pydoc
            from inspect import getargspec, formatargspec
            if not cmd:
                for f in shell_funcs:
                    doc = pydoc.getdoc(shell_funcs[f])
                    synop, full = pydoc.splitdoc(doc)
                    print "%-40s : %s" % (f + formatargspec(*getargspec(shell_funcs[f])), synop)
                print
                print "For help on a specific command, type 'hh(<command>)'"
            elif type(cmd) == str:
                try:
                    doc = pydoc.getdoc(shell_funcs[cmd])
                except KeyError:
                    print "No such command: %s" % cmd
                    return
                print doc
            else:
                doc = pydoc.getdoc(cmd)
                print doc
                
        # Break into shell
        banner =  "Welcome to volshell! Current memory image is:\n%s\n" % filename
        banner += "To get help, type 'hh()'"
        try:
            from IPython.Shell import IPShellEmbed
            shell = IPShellEmbed([], banner=banner)
            shell()
        except ImportError:
            import code, inspect

            frame = inspect.currentframe()

            # Try to enable tab completion
            try:
                import rlcompleter, readline
                readline.parse_and_bind("tab: complete")
            except: pass

            # evaluate commands in current namespace
            namespace = frame.f_globals.copy()
            namespace.update(frame.f_locals)

            code.interact(banner=banner, local=namespace)
