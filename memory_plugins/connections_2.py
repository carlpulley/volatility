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

class connections_2(forensics.commands.command):

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


    def render_text(self,outfd, data):
        outfd.write("%-6s %-25s %-25s\n"%('Pid','Local', 'Remote'))
        for(pid, local, remote, filename) in data:
            outfd.write("%-6d %-25s %-25s\n" % (pid, local, remote))
            
    def render_sql(self,outfd,data):
         conn = sqlite3.connect(outfd)
         cur = conn.cursor()

	 if not os.path.isfile(outfd):
             cur.execute("create table connections (pid integer, local text, remote text, memimage text)")
             conn.commit()

         try:
             cur.execute("select * from connections")
         except sqlite3.OperationalError:
             cur.execute("create table connections (pid integer, local text, remote text, memimage text)")
             conn.commit()

	 for (pid, local,
             remote, filename) in data:
             conn = sqlite3.connect(outfd)
             cur = conn.cursor()
             cur.execute("insert into connections values (?,?,?,?)", (pid, local, remote, filename))
	     conn.commit()

    def calculate(self):
        """
        Function prints a list of dlls loaded in each process
        """
                        
        opts, args = self.op.parse_args(self.args)        

        (addr_space, symtab, types) = load_and_identify_image(self.op, self.opts)

        filename = self.opts.filename
    
        connections = tcb_connections(addr_space, types, symtab)

        for connection in connections:
        
            if not addr_space.is_valid_address(connection):
                continue

            pid     = connection_pid(addr_space, types, connection)
            lport   = connection_lport(addr_space, types, connection)
            laddr   = connection_laddr(addr_space, types, connection)
            rport   = connection_rport(addr_space, types, connection)
            raddr   = connection_raddr(addr_space, types, connection)

            local = "%s:%d"%(laddr,lport)
            remote = "%s:%d"%(raddr,rport)

            yield(pid, local, remote, filename)
