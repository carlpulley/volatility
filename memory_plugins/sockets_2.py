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
from forensics.win32.network import *

def format_time(time):
    ts=strftime("%a %b %d %H:%M:%S %Y",
                gmtime(time))
    return ts

class sockets_2(forensics.commands.command):

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
        return  "Print connections"

    # Finally we override the forensics.commands.command.execute() method
    # which provides the plugins core functionality. Command line options
    # are accessed as attributes of self.opts. For example, the options 
    # provided by the standard parse would would provide the following
    # attributes: self.opts.filename, self.opts.base, self.opts.type.

    def render_text(self,outfd, data):
        outfd.write("%-6s %-6s %-6s %-26s\n"%('Pid','Port','Proto','Create Time'))
        for(pid,port,proto,time, memimage) in data:
            outfd.write("%-6s %-6s %-6s %-26s\n"%(pid, port, proto,time))
            
    def render_sql(self,outfd,data):
         conn = sqlite3.connect(outfd)
         cur = conn.cursor()

	 if not os.path.isfile(outfd):
             cur.execute("create table sockets (pid integer, port integer, proto text, ctime text, memimage text)")
             conn.commit()

         try:
             cur.execute("select * from sockets")
         except sqlite3.OperationalError:
             cur.execute("create table sockets (pid integer, port integer, proto text, ctime text, memimage text)")
             conn.commit()

	 for (pid, port,
             proto, ctime, filename) in data:
             conn = sqlite3.connect(outfd)
             cur = conn.cursor()
             cur.execute("insert into sockets values (?,?,?,?,?)", (pid, port, proto, ctime, filename))
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
                        
        opts, args = self.op.parse_args(self.args)        

        (addr_space, symtab, types) = load_and_identify_image(self.op, self.opts)

        filename = self.opts.filename
	
        sockets = open_sockets(addr_space, types, symtab)


        for socket in sockets:

            if not addr_space.is_valid_address(socket):
                continue

            pid   = socket_pid(addr_space, types, socket)
            proto = socket_protocol(addr_space, types, socket)
            port  = socket_local_port(addr_space, types, socket)
            time  = socket_create_time(addr_space, types, socket)
        
            yield(pid,port,proto,format_time(time), filename)
    
