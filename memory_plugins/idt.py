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

class idt(forensics.commands.command):

    # Declare meta information associated with this plugin
    
    meta_info = forensics.commands.command.meta_info 
    meta_info['author'] = 'Michael Ligh, Blake Hartstein'
    meta_info['copyright'] = 'Copyright (c) 2009 Michael Ligh, Blake Hartstein'
    meta_info['contact'] = 'michael.ligh@mnin.org'
    meta_info['license'] = 'GNU General Public License 2.0 or later'
    meta_info['url'] = 'http://www.mnin.org'
    meta_info['os'] = 'WIN_32_XP_SP2'
    meta_info['version'] = '1.0'
    
    def parser(self):
        forensics.commands.command.parser(self)

    def help(self):
        return  "Print Interrupt Descriptor Table (IDT) entries"

    def execute(self):
	
        op = self.op
        opts = self.opts

        if (opts.filename is None) or (not os.path.isfile(opts.filename)):
            op.error("File is required")
        else:
            filename = opts.filename  
			
        print "\n"
		
        (addr_space, symtab, types) = load_and_identify_image(op, opts, False)
        
        if not addr_space is None and not symtab is None:
            KPCR = 0xFFDFF000
        
            if not addr_space.is_valid_address(KPCR):
                print "KPCR is UNAVAILABLE" 
                return
    
            idt_mem = read_value(addr_space, 'unsigned long', KPCR+0x38)

            print 'IDT#\tISR\tunused_lo\tsegment_type\tsystem_segment_flag\tDPL\tP'
            
            for i in range(0, 256):
                offset = (i) * 8
                
                LowOffset = read_value(addr_space, 'unsigned short', idt_mem+0 + offset)
                selector  = read_value(addr_space, 'unsigned short', idt_mem+2 + offset)
                unused_lo = read_value(addr_space, 'unsigned char', idt_mem+4 + offset)
                options   = read_value(addr_space, 'unsigned char', idt_mem+5 + offset)
                
                segment_type = options & 0x0f
                system_segment_flag = (options & 0x10) >> 4
                DPL = (options & 0x60) >> 5
                P = (options & 0x80) >> 7
                HiOffset = read_value(addr_space, 'unsigned short', idt_mem+6 + offset)
		        
                print '%s\t%4.4x:%4.4x%4.4x\t%x' % (str(i), selector, HiOffset, LowOffset, unused_lo),
                print '\t%2.2x\t%x\t%x\t%x' % (segment_type, system_segment_flag, DPL, P) 
