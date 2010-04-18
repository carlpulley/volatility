#!/usr/bin/env python
#
#       mutantscan.py
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

from forensics.object2 import *
from forensics.object import *
from vutils import *
from forensics.win32.scan2 import *
from forensics.win32.meta_info import *

mutant_types = {
    '_KMUTANT' : [ 0x20, {
        'Header' : [ 0x0, ['_DISPATCHER_HEADER']],
        'MutantListEntry' : [ 0x10, ['_LIST_ENTRY']],
		'OwnerThread' : [ 0x18, ['pointer', ['_KTHREAD']]],
		'Abandoned' : [ 0x1c, ['unsigned char']],
		'ApcDisable' : [ 0x1d, ['unsigned char']]
    } ],
    '_OBJECT_HEADER' : [ 0x18, {
        'PointerCount' : [ 0x0, ['int']],
        'HandleCount' : [ 0x04, ['int']],
        'Type' : [ 0x08, ['pointer', ['_OBJECT_TYPE']]],
        'NameInfoOffset' : [ 0x0c, ['unsigned char']],
    } ],
    '_OBJECT_NAME_INFO' : [ 0xc, {
        'Directory' : [ 0x0, ['pointer', ['_OBJECT_DIRECTORY']]],
        'Name' : [ 0x04, ['_UNICODE_STRING']],
    } ],
    '_DISPATCHER_HEADER' : [  0x10, { 
      'Type' : [ 0x0, ['unsigned char']], 
      'Absolute' : [ 0x1, ['unsigned char']],
      'Size' : [ 0x2, ['unsigned char']], 
      'Inserted' : [0x3, ['unsigned char']],
      'SignalState' : [ 0x4, ['long']],
      'WaitListHead' : [ 0x8, ['_LIST_ENTRY']],
    } ],
}

class PoolScanMutant(GenMemScanObject):
    """ Scan for pool objects """
    def __init__(self,addr_space, silent):
        GenMemScanObject.__init__(self, addr_space)
        self.pool_tag = "\x4d\x75\x74\xe1"
        self.pool_size = 0x40
        self.silent = silent

    class Scan(PoolScanner):
        def __init__(self, poffset, outer):
            PoolScanner.__init__(self, poffset, outer)
            self.kas = meta_info.KernelAddressSpace
            # add constraints
            self.add_constraint(self.check_pooltype_nonpaged)
            self.add_constraint(self.check_poolindex_zero)
            self.add_constraint(self.check_blocksize_geq)

        def object_offset(self,found):
            return found - 4 + obj_size(self.data_types, \
                '_POOL_HEADER')

        def object_action(self,buff,object_offset):
            silent = self.outer.silent
            # check for minimum size
            AllocSize = self.get_poolsize(buff, object_offset-4)
            SizeOfMutant = obj_size(self.data_types, '_KMUTANT')
            SizeOfObjectHeader = obj_size(self.data_types, \
                '_OBJECT_HEADER')
            if SizeOfMutant+SizeOfObjectHeader > AllocSize:
                return False
                
            # build structure from higher to lower addresses
            StartOfMutant = object_offset - 8 + AllocSize - SizeOfMutant 
            OwnerThread = read_obj_from_buf(buff, self.data_types, \
                ['_KMUTANT', 'OwnerThread'], StartOfMutant)
            SignalState = read_obj_from_buf(buff, self.data_types, \
                ['_KMUTANT', 'Header', 'SignalState'], \
                StartOfMutant)
                
            if (OwnerThread >= 0x80000000) : 
                PID = read_obj(self.kas, self.data_types,\
                    ['_ETHREAD', 'Cid', 'UniqueProcess'], OwnerThread)
                TID = read_obj(self.kas, self.data_types,\
                    ['_ETHREAD', 'Cid', 'UniqueThread'], OwnerThread)
                CID = "%s:%s" % (PID, TID)
            else:
                CID = ''
                    
            StartOfObjectHeader = StartOfMutant - SizeOfObjectHeader
            ObjType = read_obj_from_buf(buff, self.data_types, \
                ['_OBJECT_HEADER', 'Type'], \
                StartOfObjectHeader)
            # suppress destructed objects
            #if (ObjType == 0xbad0b0b0):
                #return False
            Pointers = read_obj_from_buf(buff, self.data_types, \
                ['_OBJECT_HEADER', 'PointerCount'], \
                StartOfObjectHeader)
            Handles = read_obj_from_buf(buff, self.data_types, \
                ['_OBJECT_HEADER', 'HandleCount'], \
                StartOfObjectHeader)
            OfsName = read_obj_from_buf(buff, self.data_types, \
                ['_OBJECT_HEADER', 'NameInfoOffset'], \
                StartOfObjectHeader)
                
            if OfsName > 0:
                StartOfName = StartOfObjectHeader - OfsName
                Name = read_unicode_string_buf(buff, self.kas, self.data_types, \
                    ['_OBJECT_NAME_INFO', 'Name'], StartOfName) 
                if (Name == None):
                    return False
            else:
                Name = ''    
                
            if (silent):
                if (Name==None) or \
                    ((OfsName==0) and (OwnerThread==0)):
                        return False

            address = self.as_offset + object_offset
            
            print "0x%08x 0x%08x %4d %4d %6d 0x%08x %-10s %s" % \
                (address, ObjType, Pointers, Handles, SignalState, \
                OwnerThread, CID, Name)

class mutantscan(forensics.commands.command):

    # Declare meta information associated with this plugin

    meta_info = forensics.commands.command.meta_info
    meta_info['author'] = 'Andreas Schuster'
    meta_info['copyright'] = 'Copyright (c) 2009 Andreas Schuster'
    meta_info['contact'] = 'a.schuster@forensikblog.de'
    meta_info['license'] = 'GNU General Public License 2.0 or later'
    meta_info['url'] = 'http://computer.forensikblog.de/en/'
    meta_info['os'] = 'WIN_32_XP_SP2'
    meta_info['version'] = '0.2'
    
    def parser(self):

        forensics.commands.command.parser(self)

        self.op.add_option('-s', '--silent',
            help='suppress less meaningful results',
            action='store_true', dest='silent')

    def help(self):
        return  "Scan for mutant (mutex) objects"

    def execute(self):
        op = self.op
        opts = self.opts
           
        (addr_space, symtab, types) = load_and_identify_image(op, opts)
        set_kas(addr_space)
        
        # merge type information and make it globally accessible
        types.update(mutant_types)
        set_datatypes(types)
            
        try:
            flat_addr_space = FileAddressSpace(opts.filename, fast=True)
        except:
            op.error("Unable to open image file %s" %(filename))
                     
        search_addr_space = find_addr_space(flat_addr_space, types)
        scanners = []
        scanners.append((PoolScanMutant(search_addr_space, opts.silent)))
        
        print "%-10s %-10s %4s %4s %6s %-10s %-10s %s" % \
            ('Phys.Addr.', 'Obj Type', '#Ptr', '#Hnd', 'Signal',\
            'Thread', 'CID', 'Name')
        scan_addr_space(search_addr_space, scanners)
