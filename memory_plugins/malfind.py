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
import pydasm

class malfind(forensics.commands.command):

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
            help='Output directory for dumped vad sections',
            action='store', type='string', dest='dir')

        self.op.add_option('-p', '--pid',
            help='Dump the address space for this Pid',
            action='store', type='string', dest='pid')

    def help(self):
        return  "Dump and rebuild executables"

    def execute(self):
	
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
            vaddir = opts.dir
			
        if (opts.pid is None):
            print "No pid specified, searching all active processes."
			
        print "\n"
		
        # basic process listing code from pslist 
        (addr_space, symtab, types) = load_and_identify_image(op, opts)
        all_tasks = process_list(addr_space, types, symtab)
		
        # get the file name and pid for each running process
        for task in all_tasks:
            if not addr_space.is_valid_address(task):
                continue
				
            found = 0

            directory_table_base = process_dtb(addr_space, types, task)
			
            process_address_space = create_addr_space(addr_space, directory_table_base)
			
            image_file_name = process_imagename(addr_space, types, task)
            if image_file_name is None:
                image_file_name = "UNKNOWN"
				
            process_id = process_pid(addr_space, types, task)
			
            # by default, scan all processes - otherwise only scan the selected one
            if (opts.pid is None) or (int(opts.pid) == process_id):
                print "#\n# %s (Pid: %s)\n#\n" % (image_file_name, process_id)
				
                # use internal vadinfo command to acquire information on the vad sections 
                vadinfo_cmd = "python ./volatility vadinfo --pid=%s -f \"%s\"" % (process_id, filename)
                vadinfo = commands.getoutput(vadinfo_cmd).split("\n")
				
                # look for "short" vad entries                 
                for j in range(1, len(vadinfo)):
                    if "Tag VadS" in vadinfo[j]:
					
                        # isolate the vad flags (permissions), start virtual address, and end virtual address
                        flags = vadinfo[j+2].split(":")[2]
                        startaddr = vadinfo[j].split(" ")[4]
                        endaddr = vadinfo[j].split(" ")[6]
						
                        sa = int(startaddr, 16)
						
                        # filter vad sections with executable permissions 
                        if ("2" in flags) or ("3" in flags) or \
                           ("6" in flags) or ("7" in flags) or ("18" in flags):
                            print "+ %s Flags %s" % (vadinfo[j], flags)
							
                            found += 1
							
                            # dump the vad sections to disk for analysis of the suspicious section content
                            offset = process_address_space.vtop(task)
                            dmp = "%s/%s.%x.%s-%s.dmp" % (vaddir, image_file_name, offset, startaddr, endaddr)
							
                            if (not os.path.isfile(dmp)):
                                vaddump_cmd = "python ./volatility vaddump --directory=%s --pid=%s -f \"%s\"" % (vaddir, process_id, filename)
                                commands.getoutput(vaddump_cmd)
							
                            # read the contents of the dumped vad section
                            try:
                                dmpfile = open(dmp, 'rb')
                                data = dmpfile.read()
                            except:
                                print "  - Cannot open or read the file: %s" % dmp
                                continue
							
                            # very possible that the memory is paged to disk 
                            if (len(data) == 0):
                                continue
							
                            # look for MZ header at base of the dumped vad section (will find most hidden DLLs)
                            elif (data[0:2] == 'MZ'):
                                
		                        # obtain peb from process_address_space like procdump 
                                peb = process_peb(process_address_space, types, task)
                                if process_address_space.vtop(sa) == None:
                                    print "  - Error: Image base not memory resident for process [%d]" % (process_id)
                                    continue
					
                                # rebuild the exe from memory like procdump but use a more unique file name and set vad section startaddr as image base
                                rebuilt_name = "%s/%s.%d.%x.exe" % (vaddir, image_file_name, process_id, sa)
                                print "  - Status: dumping %s" % rebuilt_name
                                of = open(rebuilt_name, 'wb')
                                try:
                                    rebuild_exe_mem(process_address_space, types, sa, of, True)
                                except ValueError,ve:
                                    print "  - Unable to dump executable; sanity check failed:"
                                    print "  ", ve
                                finally:
                                    of.close()								
								
                            # disassemble the code (will find most remote threads and shell codes)
                            else:
                                offset = 0
                                max = 5
                                print "  - Status: disassembling with pydasm..."
                                while (offset < len(data)) and max > 0:
                                    k = pydasm.get_instruction(data[offset:], pydasm.MODE_32)
                                    print "   0x%x %s" % (sa+offset, pydasm.get_instruction_string(k, pydasm.FORMAT_INTEL, 0))
                                    if not k:
                                        break
                                    offset += k.length
                                    max -= 1
									
                            dmpfile.close()
                    j += 1
                print "\nFound %d suspicious Vad entries\n" % found
                     
