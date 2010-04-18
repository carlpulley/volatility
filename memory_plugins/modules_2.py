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
from forensics.win32.modules import *

class modules_2(forensics.commands.command):

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
        return  "Print list running processes"

    # Finally we override the forensics.commands.command.execute() method
    # which provides the plugins core functionality. Command line options
    # are accessed as attributes of self.opts. For example, the options 
    # provided by the standard parse would would provide the following
    # attributes: self.opts.filename, self.opts.base, self.opts.type.

    def render_text(self,outfd, data):
        outfd.write("%-50s %-12s %-8s %s\n" %('File','Base', 'Size', 'Name'))

        for (file, base, size, name, memimage) in data:
            outfd.write("%-50s %s 0x%06x %s\n" %(file, base, size, name))
            
    def render_sql(self,outfd,data):
         conn = sqlite3.connect(outfd)
         cur = conn.cursor()

	 if not os.path.isfile(outfd):
             cur.execute("create table modules (file text, base text, size text, name text, memimage text)")
             conn.commit()

         try:
             cur.execute("select * from modules")
         except sqlite3.OperationalError:
             cur.execute("create table modules (file text, base text, size text, name text, memimage text)")
             conn.commit()

	 for (file,base,size,
             name, filename) in data:
             conn = sqlite3.connect(outfd)
             cur = conn.cursor()
             cur.execute("insert into modules values (?,?,?,?,?)", (file, base, size, name, filename))
	     conn.commit()

    def calculate(self):
        op = get_standard_parser(self.cmdname)
       
        opts, args = op.parse_args(self.args)        

        (addr_space, symtab, types) = load_and_identify_image(op, self.opts)

        filename = self.opts.filename
        
        all_modules = modules_list(addr_space, types, symtab)


        for module in all_modules:
            if not addr_space.is_valid_address(module):
                continue
            module_image = module_imagename(addr_space, types, module)
            if module_image is None:
                module_image = "UNKNOWN"
            
            module_name = module_modulename(addr_space, types, module)
            if module_name is None:
                module_name = "UNKNOWN"

            module_base = module_baseaddr(addr_space, types, module)
            if module_base is None:
                module_base = "UNKNOWN"
            else:
                module_base = "0x%010x" % module_base

            module_size = module_imagesize(addr_space, types, module)
           
            yield(module_image, module_base, module_size, module_name, filename)
