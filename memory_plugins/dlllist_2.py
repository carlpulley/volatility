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
@author:       AAron Walters
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com
@organization: Volatile Systems
"""

import sqlite3
from vutils import *
from forensics.win32.tasks import *

class dlllist_2(forensics.commands.command):

    # Declare meta information associated with this plugin
    
    meta_info = dict(
        author = 'AAron Walters',
        copyright = 'Copyright (c) 2007,2008 AAron Walters',
        contact = 'awalters@volatilesystems.com',
        license = 'GNU General Public License 2.0 or later',
        url = 'https://www.volatilesystems.com/default/volatility',
        os = 'WIN_32_XP_SP2',
        version = '1.0')

    
        
    # This module makes use of the standard parser. Thus it is not 
    # necessary to override the forensics.commands.command.parse() method.
    # The standard parser provides the following command line options:
    #    '-f', '--file', '(required) Image file'
    #    '-b', '--base', '(optional) Physical offset (in hex) of DTB'
    #    '-t', '--type', '(optional) Identify the image type'


    # We need to override the forensics.commands.command.help() method to
    # change the user help message.  This function returns a string that 
    # will be displayed when a user lists available plugins.

    def help(self):
        return  "Print dlls"

    # Finally we override the forensics.commands.command.execute() method
    # which provides the plugins core functionality. Command line options
    # are accessed as attributes of self.opts. For example, the options 
    # provided by the standard parse would would provide the following
    # attributes: self.opts.filename, self.opts.base, self.opts.type.

    def render_text(self,outfd, data):
        outfd.write("%-20s %-6s %-26s %-20s %-16s %-26s\n" % (
                'Name', 'Pid', 'cmdline', 'base', 'size', 'path'))

        for (image_file_name, process_id,command_line,base,size,path, memimage) in data:

            outfd.write("%-20s %-6s %-26s %-20s %-16s %-26s\n" % (
                image_file_name, 
                process_id,
                command_line,
                base,
                size,
                path))                

            
    def render_sql(self,outfd,data):
         conn = sqlite3.connect(outfd)
         cur = conn.cursor()

	 if not os.path.isfile(outfd):
             cur.execute("create table dlls (image_file_name text, pid integer, cmdline text, base text, size text, path text, memimage text)")
             conn.commit()

         try:
             cur.execute("select * from dlls")
         except sqlite3.OperationalError:
             cur.execute("create table dlls (image_file_name text, pid integer, cmdline text, base text, size text, path text, memimage text)")
             conn.commit()

	 for (image_file_name,
             process_id,
             command_line,
             base,
             size,
             path,
             filename) in data:
             conn = sqlite3.connect(outfd)
             cur = conn.cursor()
             cur.execute("insert into dlls values (?,?,?,?,?,?,?)", 
                 (image_file_name, process_id, command_line, base, size, path, filename))
	     conn.commit()

    def parser(self):
       
        forensics.commands.command.parser(self)

        self.op.remove_option('-b')
        self.op.remove_option('-t')

        self.op.add_option('-o', '--offset',
            help='EPROCESS Offset (in hex) in physical address space',
            action='store', type='string', dest='offset')

        self.op.add_option('-p', '--pid',
            help='Get info for this Pid',
            action='store', type='int', dest='pid')

    def calculate(self):
        """
        Function prints a list of dlls loaded in each process
        """
                        

        opts, args = self.op.parse_args(self.args)        

        (addr_space, symtab, types) = load_and_identify_image(self.op, self.opts)

        filename = self.opts.filename

        if not opts.offset is None:
 
            try:
                offset = int(opts.offset, 16)
            except:
                op.error("EPROCESS offset must be a hexidecimal number.")
        
            try:
                flat_address_space = FileAddressSpace(filename)
            except:
                op.error("Unable to open image file %s" %(filename))

            directory_table_base = process_dtb(flat_address_space, types, offset)

            process_address_space = create_addr_space(addr_space, directory_table_base)

            if process_address_space is None:
                print "Error obtaining address space for process [%d]" % (process_id)
                return


            image_file_name = process_imagename(flat_address_space, types, offset)

            process_id = process_pid(flat_address_space, types, offset)
                            
            peb = process_peb(flat_address_space, types, offset)

            if not process_address_space.is_valid_address(peb):
                #print "Unable to read PEB for task."
                command_line = "UNKNOWN"
                return

            command_line = process_command_line(process_address_space, types, peb)

            if command_line is None:
                command_line = "UNKNOWN"

                 
            modules = process_ldrs(process_address_space, types, peb)

            #if len(modules) > 0:
                #print "%-12s %-12s %s"%('Base','Size','Path')
        
            for module in modules:
                if not process_address_space.is_valid_address(module):
                    return
                path = module_path(process_address_space, types, module)
                if path is None:
                    path = "UNKNOWN"
                
                base = module_base(process_address_space, types, module)
                if base is None:
                    base = "UNKNOWN"
                else:
                    base = "0x" % (base)
                
                size = module_size(process_address_space, types, module)
                if size is None:
                    size = "UNKNOWN"
                else:
                    size = "0x" % (size)
                
                yield (image_file_name, process_id,command_line,base,size,path)            
            
        else:
    
            # get list of windows processes
            all_tasks = process_list(addr_space, types, symtab)        

            if not opts.pid == None:
                all_tasks = process_find_pid(addr_space,types, symtab, all_tasks, opts.pid)
                if len(all_tasks) == 0:
                    print "Error process [%d] not found"%opts.pid

    
            for task in all_tasks:

                if not addr_space.is_valid_address(task):
                    continue
            
                #if len(all_tasks) > 1:
                #    print "%s"%star_line
        
                image_file_name = process_imagename(addr_space, types, task)

                process_id = process_pid(addr_space, types, task)

                process_address_space = process_addr_space(addr_space, types, task, opts.filename)

                if process_address_space is None:
                    print "Error obtaining address space for process [%d]" % (process_id)
                    continue
                            
                peb = process_peb(addr_space, types, task)

                if not process_address_space.is_valid_address(peb):
                    #print "Unable to read PEB for task."
                    command_line = "UNKNOWN"
                    continue
                else:
                    command_line = process_command_line(process_address_space, types, peb)

                if command_line is None:
                    command_line = "UNKNOWN"

                #print "Command line : %s" % (command_line)
      
                #print "something below"
                #print read_unicode_string(process_address_space, types,
                #    ['_PEB', 'CSDVersion'], peb)
        
                modules = process_ldrs(process_address_space, types, peb)

                #if len(modules) > 0:
                #    print "%-12s %-12s %s"%('Base','Size','Path')
        
                for module in modules:
                    if not process_address_space.is_valid_address(module):
                        continue
                    path = module_path(process_address_space, types, module)
                    if path is None:
                        path = "UNKNOWN"
                
                    base = module_base(process_address_space, types, module)
                    if base is None:
                        base = "UNKNOWN"
                    else:
                        base = "0x%1x" % (base)
                
                    size = module_size(process_address_space, types, module)
                    if size is None:
                        size = "UNKNOWN"
                    else:
                        size = "0x%1x" % (size)
                
                    yield (image_file_name, process_id,command_line,base,size,path, filename)            
 
