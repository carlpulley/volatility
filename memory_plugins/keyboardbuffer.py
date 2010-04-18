#!/usr/bin/env python
#
#       keyboardbuffer.py
#       
#       Copyright 2009 Andreas Schuster <a.schuster@yendor.net>
#       
#       This program is free software; you can redistribute it and/or modify
#       it under the terms of the GNU General Public License as published by
#       the Free Software Foundation; either version 2 of the License, or
#       (at your option) any later version.
#       
#       This program is distributed in the hope that it will be useful,
#       but WITHOUT ANY WARRANTY; without even the implied warranty of
#       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#       GNU General Public License for more details.
#       
#       You should have received a copy of the GNU General Public License
#       along with this program; if not, write to the Free Software
#       Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#       MA 02110-1301, USA.

"""
@author:       Andreas Schuster
@license:      GNU General Public License 2.0 or later
@contact:      a.schuster@forensikblog.de
@organization: http://computer.forensikblog.de/en/
"""

from vutils import *
from struct import unpack


class keyboardbuffer(forensics.commands.command):

    # Declare meta information associated with this plugin
    
    meta_info = forensics.commands.command.meta_info 
    meta_info['author'] = 'Andreas Schuster'
    meta_info['copyright'] = 'Copyright (c) 2009 Andreas Schuster'
    meta_info['contact'] = 'a.schuster@forensikblog.de'
    meta_info['license'] = 'GNU General Public License 2.0 or later'
    meta_info['url'] = 'http://computer.forensikblog.de/en/'
    meta_info['os'] = 'WIN_32_XP_SP2'
    meta_info['version'] = '0.1'
    
    def help(self):
        return  "Print BIOS keyboard buffer"    
        
    def execute(self):

        op = self.op
        opts = self.opts   

        if (opts.filename is None) or (not os.path.isfile(opts.filename)) :
            op.error("File is required")
        else:
            filename = opts.filename 
            
        try:
            flat_address_space = FileAddressSpace(filename,fast=True)
        except:
            op.error("Unable to open image file %s" %(filename))
            
        addr_space = find_addr_space(flat_address_space, types)
        
        try:
            # BIOS data area starts at 0x400 
            data = addr_space.read(0x480, 4)
            (BufferStart, BufferEnd) = unpack("HH", data)
        except:
            print "Memory image does not contain a BIOS data area."
            return
            
        # some BIOSes do not provide start and end values,
        # apply defaults
        if (BufferStart == 0 or BufferEnd == 0):
            print "Memory image does not provide buffer address, assuming defaults."
            BufferStart = 0x1e
            BufferEnd = 0x3e
        
        BufferLength = BufferEnd - BufferStart
        
        print "Buffer start: 0x%0x" % BufferStart
        print "Buffer end  : 0x%0x" % BufferEnd
        
        data = addr_space.read(0x41a, 4)
        (BufferNext, BufferLast) = unpack("HH", data)
        
        if (
                BufferNext < BufferStart or 
                BufferNext > BufferEnd or
                BufferLast < BufferStart or
                BufferLast > BufferEnd
            ):
            print "Memory image does not contain a BIOS data area."
            return

        print "Next char   : 0x%x" % BufferNext
        print "Last read   : 0x%x" % BufferLast
                        
        if (BufferLength):
            data = addr_space.read(0x400+BufferStart, BufferLength)   
            print "Buffer      : "
            for i in range(BufferStart, BufferEnd):
                (char,) = unpack("B", data[i-BufferStart])
                if (BufferNext == BufferLast and BufferNext == i):
                    comment = "<-- Next/Last"
                elif (i == BufferNext): 
                    comment = "<-- Next"
                elif (i == BufferLast):
                    comment = "<-- Last"
                else:
                    comment = ""
                print "\t0x%x: 0x%02x %s" % (i, char, comment) 
