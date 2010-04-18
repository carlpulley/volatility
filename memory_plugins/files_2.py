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
from forensics.win32.handles import *

def find_count(outfd, process_id, file_name):
    conn = sqlite3.connect(outfd)
    cur = conn.cursor()

    for c in cur.execute("select num from files where pid = ? and file = ?",(process_id, file_name)):
        if c[0] >= 0:
            temp = c[0] + 1
        else:
            temp = 0
        return temp
    return 0


def print_entry_file2(addr_space, types, entry):

    if not addr_space.is_valid_address(entry):
        return

    obj = handle_entry_object(addr_space, types, entry)
    if obj is None:
        return
    
    if addr_space.is_valid_address(obj):
        if is_object_file(addr_space, types, obj):
            file = object_data(addr_space, types, obj)
            fname = file_name(addr_space, types, file)
            if fname != "":
                #print "%-6s %-40s"%("File",fname)
		return fname

class files_2(forensics.commands.command):

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
        return  "Print files"


    # Finally we override the forensics.commands.command.execute() method
    # which provides the plugins core functionality. Command line options
    # are accessed as attributes of self.opts. For example, the options 
    # provided by the standard parse would would provide the following
    # attributes: self.opts.filename, self.opts.base, self.opts.type.

    def render_text(self,outfd, data):
        outfd.write("%-7s %-16s\n" % ('Pid', 'Filename'))

        for (process_id, file_name, memimage) in data:
            if file_name != None:
                outfd.write("%-7s %-16s\n" % (
                    process_id, file_name))                

    
    def render_sql(self,outfd,data):
         conn = sqlite3.connect(outfd)
         cur = conn.cursor()

	 if not os.path.isfile(outfd):
             cur.execute("create table files (pid, file, num, memimage)")
             conn.commit()

         try:
             cur.execute("select * from files")
         except sqlite3.OperationalError:
             cur.execute("create table files (pid, file, num, memimage)")
             conn.commit()

	 for (process_id, file_name, memimage) in data:
             if file_name != None:
                 conn = sqlite3.connect(outfd)
                 cur = conn.cursor()
                 temp = find_count(outfd, process_id, file_name)
                 if temp == 0:
                     cur.execute("insert into files values (?,?,?,?)", (process_id, file_name, 1, memimage))
                 else:
                     cur.execute("update files set num = ? where pid = ? and file = ? and memimage = ?", (temp, process_id, file_name, memimage))
                 conn.commit()

    def parser(self):

        forensics.commands.command.parser(self)

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

        htables = []
	
        opts, args = self.op.parse_args(self.args)        

        (addr_space, symtab, types) = load_and_identify_image(self.op, self.opts)

        filename = self.opts.filename
        pid = opts.pid

        if not opts.offset is None:
 
            try:
                offset = int(opts.offset, 16)
            except:
                op.error("EPROCESS offset must be a hexidecimal number.")
        
            try:
                flat_address_space = FileAddressSpace(filename)
            except:
                op.error("Unable to open image file %s" %(filename))

            ObjectTable = process_handle_table(flat_address_space, types, offset)

            if addr_space.is_valid_address(ObjectTable):
                htables.append(ObjectTable)
        
        else:

            htables = handle_tables(addr_space, types, symtab, pid)


        for table in htables:
          
            process_id = handle_process_id(addr_space, types, table)
            if process_id == None:
                continue

            entries = handle_entries(addr_space, types, table)
            for hentry in entries:
                fname = print_entry_file2(addr_space, types, hentry)
                yield(process_id, fname, filename)         
 
