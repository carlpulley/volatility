#!/usr/bin/env python
#
#       symlinkobjscan.py
#       
#       Copyright 2009 Andreas Schuster <a.schuter@yendor.net>
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

from forensics.object2 import *
from forensics.object import *
from vutils import *
from forensics.win32.scan2 import *
from forensics.win32.meta_info import *
from forensics.win32.datetime import read_time_buf

symlink_types = {
    '_SYMLINK_OBJECT' : [ 0x20, {
        'CreatedTime' : [ 0x0, ['_KSYSTEM_TIME']],
        'Target' : [ 0x8, ['_UNICODE_STRING']],        
    } ],
    '_OBJECT_HEADER' : [ 0x18, {
        'PointerCount' : [ 0x0, ['int']],
        'HandleCount' : [ 0x4, ['int']],
        'Type' : [ 0x8, ['pointer', ['_OBJECT_TYPE']]],
        'NameInfoOffset' : [ 0x0c, ['unsigned char']],
        'HandleInfoOffset' : [ 0xd, ['unsigned char']],    
        'QuotaInfoOffset' : [ 0xe, ['unsigned char']],
        'Flags' : [ 0xf, ['unsigned char']],
        'ObjectCreateInfo' : [ 0x10, ['pointer']],
        'SecurityDescriptor' : [ 0x14, ['pointer']],
    } ],
    '_OBJECT_NAME_INFO' : [ 0x10, {
        'Directory' : [ 0x0, ['pointer', ['_OBJECT_DIRECTORY']]],
        'Name' : [ 0x04, ['_UNICODE_STRING']],
    } ],
}

class PoolScanSymlink(GenMemScanObject):
    """ Scan for pool objects """
    def __init__(self, addr_space):
        GenMemScanObject.__init__(self, addr_space)
        self.pool_tag = "\x53\x79\x6d\xe2"
        self.pool_size = 0x50

    class Scan(PoolScanner):
        def __init__(self, poffset, outer):
            PoolScanner.__init__(self, poffset, outer)
            self.kas = meta_info.KernelAddressSpace
            # add constraints
            self.add_constraint(self.check_pooltype_paged)
            self.add_constraint(self.check_poolindex_nonzero)
            self.add_constraint(self.check_blocksize_equal)

        def object_offset(self,found):
            return found - 4 + obj_size(self.data_types, \
                '_POOL_HEADER')
                
        def object_action(self,buff,object_offset):
            # check for minimum size
            AllocSize = self.get_poolsize(buff, object_offset-4)
            SizeOfSymlink = obj_size(self.data_types, '_SYMLINK_OBJECT')
            SizeOfObjectHeader = obj_size(self.data_types, \
                '_OBJECT_HEADER')
            SizeOfObjectName = obj_size(self.data_types, \
                '_OBJECT_NAME_INFO')
            if SizeOfSymlink+SizeOfObjectHeader+SizeOfObjectName > AllocSize:
                return False

            # build structure from higher to lower addresses
            StartOfSymlink = object_offset - 8 + AllocSize - SizeOfSymlink 
            CreatedTime = read_time_buf(buff, self.data_types, \
                ['_SYMLINK_OBJECT', 'CreatedTime'], StartOfSymlink)
            Target = read_unicode_string_buf(buff, self.kas, self.data_types, \
                ['_SYMLINK_OBJECT', 'Target'], StartOfSymlink)
            if Target == None:
                return False
                
            StartOfObjectHeader = StartOfSymlink - SizeOfObjectHeader
            ObjType = read_obj_from_buf(buff, self.data_types, \
                ['_OBJECT_HEADER', 'Type'], \
                StartOfObjectHeader)
            if ObjType == None:
                return False
            Pointers = read_obj_from_buf(buff, self.data_types, \
                ['_OBJECT_HEADER', 'PointerCount'], \
                StartOfObjectHeader)
            Handles = read_obj_from_buf(buff, self.data_types, \
                ['_OBJECT_HEADER', 'HandleCount'], \
                StartOfObjectHeader)
            OfsName = read_obj_from_buf(buff, self.data_types, \
                ['_OBJECT_HEADER', 'NameInfoOffset'], \
                StartOfObjectHeader)
                
            HandleInfoOffset = read_obj_from_buf(buff, self.data_types, \
                ['_OBJECT_HEADER', 'HandleInfoOffset'], \
                StartOfObjectHeader)
                
            if OfsName > 0:
                StartOfName = StartOfObjectHeader - OfsName
                Name = read_unicode_string_buf(buff, self.kas, self.data_types, \
                    ['_OBJECT_NAME_INFO', 'Name'], \
                    StartOfName)
                if Name == None:
                    return False
            else:
                Name = ''    
                
            address = self.as_offset + object_offset
            
            print "0x%08x 0x%08x %4d %4d %-25s %s -> %s" % \
                (address, ObjType, Pointers, Handles, \
                self.format_time(CreatedTime), Name, Target)

class symlinkobjscan(forensics.commands.command):

    # Declare meta information associated with this plugin

    meta_info = forensics.commands.command.meta_info
    meta_info['author'] = 'Andreas Schuster'
    meta_info['copyright'] = 'Copyright (c) 2009 Andreas Schuster'
    meta_info['contact'] = 'a.schuster@forensikblog.de'
    meta_info['license'] = 'GNU General Public License 2.0 or later'
    meta_info['url'] = 'http://computer.forensikblog.de/en/'
    meta_info['os'] = 'WIN_32_XP_SP2'
    meta_info['version'] = '0.2'

    def help(self):
        return  "Scan for symbolic link objects"

    def execute(self):
        op = self.op
        opts = self.opts
           
        (addr_space, symtab, types) = load_and_identify_image(op, opts)
        set_kas(addr_space)
                
        # merge type information and make it globally accessible
        types.update(symlink_types)
        set_datatypes(types)

        try:
            flat_addr_space = FileAddressSpace(opts.filename, fast=True)
        except:
            op.error("Unable to open image file %s" %(filename))
            
        search_addr_space = find_addr_space(flat_addr_space, types)
        scanners = []
        scanners.append((PoolScanSymlink(search_addr_space)))

        print "%-10s %-10s %4s %4s %-25s %s -> %s" % \
            ('Phys.Addr.', 'Obj Type', '#Ptr', '#Hnd', 'Time created', \
            'Name', 'Target')
        scan_addr_space(search_addr_space, scanners)
