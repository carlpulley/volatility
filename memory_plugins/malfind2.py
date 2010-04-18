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
from forensics.win32.vad import *
import string
import sys

try:
    import yara
except ImportError:
    print "YARA is not installed, see http://code.google.com/p/yara-project/"
    
try:
    import pydasm
except ImportError:
    print "pydasm/libdasm is not installed, see http://dkbza.org/pydasm.html"
    
try:
    import pefile
except ImportError:
    print "pefile is not installed, see http://code.google.com/p/pefile/"

def rebuild_pe(addr_space, types, pe_base, pe_filename):

    pe = None

    try:
        f = open(pe_filename, 'wb')
        rebuild_exe_mem(addr_space, types, pe_base, f, True)
        f.close()
        
        if sys.modules.has_key('pefile'):
        
            pe = pefile.PE(pe_filename, fast_load=True)
            pe.parse_data_directories( directories=[ 
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS'] ] )
    except:
        print "Error dumping or parsing %s" % pe_filename
        pass

    return pe

def get_vad_range(process_address_space, StartingVpn, EndingVpn):
    Range = EndingVpn - StartingVpn + 1
    NumberOfPages = Range >> 12
    range_data = '' 

    if (StartingVpn == 0) or (EndingVpn > 0x7FFFFFFF):
        return range_data

    for i in range(0, NumberOfPages):
        page_addr = StartingVpn+i*0x1000
        if not process_address_space.is_valid_address(page_addr):
            continue

        page_read = process_address_space.read(page_addr, 0x1000)
        if page_read == None:
            range_data = range_data + ('\0' * 0x1000)
        else:
            range_data = range_data + page_read

    return range_data

def dump_to_file(name, data):
    f = open(name, "wb")
    f.write(data)
    f.close()

# hexdump formula from http://code.activestate.com/recipes/142812/ 

FILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])

def dump2(src, start=0, length=16):
    result=[]
    for i in xrange(0, len(src), length):
        s = src[i:i+length]
        hexa = ' '.join(["%02x"%ord(x) for x in s])
        printable = s.translate(FILTER)
        result.append("0x%08x   %-*s   %s\n" % (i+start, length*3, hexa, printable))
    return ''.join(result)

class malfind2(forensics.commands.command):

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
            help='Output directory for extracted data',
            action='store', type='string', dest='dir')

        self.op.add_option('-p', '--pid',
            help='Examine this pid only',
            action='store', type='int', dest='pid')
            
        self.op.add_option('-y', '--yararules',
            help='Path to YARA signatures file',
            action='store', type='string', dest='yararules')

    def help(self):
        return "[VAP] Detect hidden and injected code"

    def execute(self):

        op = self.op
        opts = self.opts
        yara_rules = None

        if (opts.filename == None) or (not os.path.isfile(opts.filename)):
            op.error("File is required")
        else:
            filename = opts.filename

        if (opts.dir == None):
            op.error("Directory is required")
        else:
            if not os.path.isdir(opts.dir):
                os.mkdir(opts.dir)
                if not os.path.isdir(opts.dir):
                    op.error("Cannot create output directory")
                    
        if (opts.yararules != None):
            if not os.path.isfile(opts.yararules):
                op.error("Cannot find YARA rules file")
            yara_rules = yara.compile(opts.yararules)

        print "\n", '#' * 25, 'Malfind Report', '#' * 25, "\n"

        (addr_space, symtab, types) = load_and_identify_image(op, opts)
        all_tasks = process_list(addr_space, types, symtab)

        for task in all_tasks:
        
            if not addr_space.is_valid_address(task):
                continue

            directory_table_base = process_dtb(addr_space, types, task)
            process_id = process_pid(addr_space, types, task)
            
            image_file_name = process_imagename(addr_space, types, task)
            if image_file_name is None:
                image_file_name = "UNKNOWN"

            # by default, scan all processes - otherwise only scan the selected one
            
            if (opts.pid != None) and (process_id != opts.pid):
                continue

            print "#\n# %s (Pid: %s)\n#\n" % (image_file_name, process_id)
            
            process_address_space = create_addr_space(addr_space, directory_table_base)
            if process_address_space == None:
                print "[!] Error obtaining address space for process [%d]\n" % (process_id)
                continue

            VadRoot = process_vadroot(addr_space, types, task)
            if VadRoot == None or not process_address_space.is_valid_address(VadRoot):
                print "[!] Error obtaining VAD root for process [%d]\n" % (process_id)
                continue

            vadlist = []
            traverse_vad(None, process_address_space, types, VadRoot, append_entry, None, None, 0, vadlist)
            
            for vad_entry in vadlist: 
                tag_addr = vad_entry - 0x4
                if not process_address_space.is_valid_address(tag_addr):
                    continue

                tag = process_address_space.read(tag_addr,4)
                StartingVpn = read_obj(process_address_space, types, ['_MMVAD_LONG', 'StartingVpn'], vad_entry)
                StartingVpn = StartingVpn << 12
                
                EndingVpn = read_obj(process_address_space, types, ['_MMVAD_LONG', 'EndingVpn'], vad_entry)
                OriginalVpn = EndingVpn
                EndingVpn = ((EndingVpn+1) << 12) - 1         
                
                #print "[!] Range: 0x%08x - 0x%08x (0x%x 0x%x bytes)" % (StartingVpn, EndingVpn, OriginalVpn, OriginalVpn-StartingVpn)

                (u_offset, tmp) = get_obj_offset(types, ['_MMVAD_LONG', 'u'])
                Flags = read_value(process_address_space, 'unsigned long', u_offset+vad_entry)
                Protection = (Flags & get_mask_flag('_MMVAD_FLAGS', 'Protection')) >> 24
                
                #range_data = ''
                range_data = get_vad_range(process_address_space, StartingVpn, EndingVpn) 
                
                # make sure we got a page and that it doesn't contain all zeros
                
                if len(range_data) < 0x1000:
                    continue
                    
                if range_data.count(chr(0)) == len(range_data):
                    continue
                    
                matches = []
                suspicious = False
                
                # scan the memory with yara
                    
                if yara_rules != None:
                    matches = yara_rules.match(data=range_data)
                
                # mark memory as suspicious based on this criteria
                
                if (tag == "VadS") and \
                   ((Protection == 0x2) or \
                   (Protection == 0x3) or \
                   (Protection == 0x6) or \
                   (Protection == 0x7) or \
                   (Protection == 0x18)):

                   suspicious = True
                   
                if len(matches) == 0 and not suspicious:
                    continue 
                    
                print "[!] Range: 0x%08x - 0x%08x (Tag: %s, Protection: 0x%x)" % (StartingVpn, EndingVpn, tag, Protection)
                ofname = "%s/malfind.%d.%x-%x.dmp" % (opts.dir, process_id, StartingVpn, EndingVpn) 
                
                print "Dumping to %s" % ofname
                dump_to_file(ofname, range_data)

                # Found a PE file, dump a rebuilt copy
               
                if range_data[0:2] == 'MZ':
                    pe = rebuild_pe(process_address_space, types, StartingVpn, ofname)
                   
                    if pe != None:
                        secinfo = ""
                        for sec in pe.sections:
                            secinfo += "%s, " % sec.Name.replace('\0', '')
                           
                        print "PE sections: [%s]" % secinfo
                       
                        # Fixup the ImageBase in case we plan to open in IDA
                       
                        if hasattr(pe, 'OPTIONAL_HEADER'):
                            pe.OPTIONAL_HEADER.ImageBase = StartingVpn
                            pe.write(ofname)
                            
                    print ""
                      
                # For non-PE files, show a hexdump and disassembly
                      
                else:
                    size = len(range_data) if len(range_data) < 32 else 32
                   
                    print "Hexdump:\n", dump2(range_data[0:size], StartingVpn)
                    
                    if sys.modules.has_key('pydasm'):
                        print "Disassembly:"
                        offset = 0
                        while (offset < size):
                            k = pydasm.get_instruction(range_data[offset:], pydasm.MODE_32)
                            print "0x%08x   %s" % (StartingVpn+offset, pydasm.get_instruction_string(k, pydasm.FORMAT_INTEL, StartingVpn))
                            if not k:
                                break
                            offset += k.length

                    print ""

                if len(matches) > 0:
                    for m in matches:
                        print "YARA rule: %s" % m.rule
                        if m.meta.has_key('description'):
                            print "Description: %s" % m.meta['description']
                        for key,value in m.strings.iteritems():
                            makehex = False
                            for char in value:
                                if char not in string.printable:
                                    makehex = True
                                    break
                            if makehex == True:
                                value = binascii.hexlify(value)
                            print "Hit: %s" % (value)
                            print dump2(range_data[key:key+32], StartingVpn+key)
                        
                    #print ""