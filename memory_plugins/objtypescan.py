#!/usr/bin/env python
#
#       objtypescan.py
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

objtype_types = {
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
    '_OBJECT_CREATOR_INFO' : [ 0x10, {
        'ObjectList' : [ 0x0, ['_LIST_ENTRY']],
        'UniqueProcessId' : [ 0x8, ['unsigned long']],
    } ],
    '_OBJECT_NAME_INFO' : [ 0xc, {
        'Directory' : [ 0x0, ['pointer', ['_OBJECT_DIRECTORY']]],
        'Name' : [ 0x04, ['_UNICODE_STRING']],
    } ],    
  '_OBJECT_TYPE' : [ 0x190, { 
        'Mutex' : [0x0, ['_ERESOURCE']],
        'TypeList' : [0x38, ['_LIST_ENTRY']],
        'Name' : [ 0x40, ['_UNICODE_STRING']], 
        'DefaultObject' : [ 0x48, ['pointer']],
        'Index' : [ 0x4c, ['unsigned long']],
        'TotalNumberOfObjects' : [ 0x50, ['unsigned long']],
        'TotalNumberOfHandles' : [ 0x54, ['unsigned long']],
        'HighWaterNumberOfObjects' : [ 0x58, ['unsigned long']],
        'HighWaterNumberOfHandles' : [ 0x5c, ['unsigned long']],
        'TypeInfo' : [ 0x60, ['_OBJECT_TYPE_INITIALIZER']],
        'Key' : [ 0xac, ['array', 4, ['unsigned char']]],
        'ObjectLocks' : [ 0xb0, ['array', 4, ['_ERESOURCE']]],
    } ],
    '_OBJECT_TYPE_INITIALIZER' : [ 0x4c, {
        'Length' : [ 0x0, ['unsigned short']],
        'UseDefaultObject' : [ 0x2, ['unsigned char']],
        'CaseInsensitive' : [ 0x3, ['unsigned char']],
        'InvalidAttributes' : [ 0x4, ['unsigned long']],
        'GenericMapping' : [ 0x8, ['_GENERIC_MAPPING']],
        'ValidAccessMask' : [ 0x18, ['unsigned long']],
        'SecurityRequired' : [ 0x1c, ['unsigned char']],
        'MaintainHandleCount' : [ 0x1d, ['unsigned char']],
        'MaintainTypeList' : [ 0x1e, ['unsigned char']],
        'PoolType' : [ 0x20, ['unsigned long']],
        'DefaultPagedPoolCharge' : [ 0x24, ['unsigned long']],
        'DefaultNonPagedPoolCharge' : [ 0x28, ['unsigned long']],
        'DumpProcedure' : [ 0x2c, ['pointer']],
        'OpenProcedure' : [ 0x30, ['pointer']],
        'CloseProcedure' : [ 0x34, ['pointer']],
        'DeleteProcedure' : [ 0x38, ['pointer']],
        'ParseProcedure' : [ 0x3c, ['pointer']],
        'SecurityProcedure' : [ 0x40, ['pointer']],
        'QueryNameProcedure' : [ 0x44, ['pointer']],
        'OkayToCloseProcedure' : [ 0x48, ['pointer']],
    } ],
}


class PoolScanObjtype(GenMemScanObject):
    """ Scan for pool objects """
    def __init__(self,addr_space):
        GenMemScanObject.__init__(self, addr_space)
        self.pool_tag = "\x4f\x62\x6a\xd4"
        self.pool_size = 0x1d0

    class Scan(PoolScanner):
        def __init__(self, poffset, outer):
            PoolScanner.__init__(self, poffset, outer)
            self.kas = meta_info.KernelAddressSpace
            # add constraints
            self.add_constraint(self.check_pooltype_nonpaged)
            self.add_constraint(self.check_poolindex_zero)
            self.add_constraint(self.check_blocksize_equal)
            
            # prepare for physical-to-virtual address conversion
            # adopted from the "strings" module
            self.reverse_map = {}
            for vpage in range(0x80000000, 0xffffffff, 0x1000):
                kpage = self.kas.vtop(vpage)
                if not kpage is None:
                    self.reverse_map[kpage] = vpage            

        def object_offset(self,found):
            return found - 4 + obj_size(self.data_types, \
                '_POOL_HEADER')

        def object_action(self,buff,object_offset):
            AllocSize = self.get_poolsize(buff, object_offset-4)
            SizeOfObjType = obj_size(self.data_types, '_OBJECT_TYPE')
            SizeOfObjectHeader = obj_size(self.data_types, \
                '_OBJECT_HEADER')
                
            # build structure from higher to lower addresses
            StartOfObjType = object_offset - 8 + AllocSize - SizeOfObjType
            ObjTypeName = read_unicode_string_buf(buff, self.kas, self.data_types, \
                ['_OBJECT_TYPE', 'Name'], StartOfObjType)
            if ObjTypeName == None:
                return False
            PoolTag = read_string_buf(buff, self.data_types, \
                ['_OBJECT_TYPE', 'Key'], StartOfObjType, 4)
            ObjectsCnt = read_obj_from_buf(buff, self.data_types, \
                ['_OBJECT_TYPE', 'TotalNumberOfObjects'], StartOfObjType)
            ObjectsHw = read_obj_from_buf(buff, self.data_types, \
                ['_OBJECT_TYPE', 'HighWaterNumberOfObjects'], StartOfObjType)
            HandlesCnt = read_obj_from_buf(buff, self.data_types, \
                ['_OBJECT_TYPE', 'TotalNumberOfHandles'], StartOfObjType)
            HandlesHw = read_obj_from_buf(buff, self.data_types, \
                ['_OBJECT_TYPE', 'HighWaterNumberOfHandles'], StartOfObjType)
            PoolType = read_obj_from_buf(buff, self.data_types, \
                ['_OBJECT_TYPE', 'TypeInfo', 'PoolType'], StartOfObjType)

                        
            StartOfObjectHeader = StartOfObjType - SizeOfObjectHeader
            ObjType = read_obj_from_buf(buff, self.data_types, \
                ['_OBJECT_HEADER', 'Type'], \
                StartOfObjectHeader)
            if ObjType == None:
                return False
            # suppress destructed objects
            if (ObjType == 0xbad0b0b0):
                return False
            Pointers = read_obj_from_buf(buff, self.data_types, \
                ['_OBJECT_HEADER', 'PointerCount'], \
                StartOfObjectHeader)
            Handles = read_obj_from_buf(buff, self.data_types, \
                ['_OBJECT_HEADER', 'HandleCount'], \
                StartOfObjectHeader)
            Flags = read_obj_from_buf(buff, self.data_types, \
                ['_OBJECT_HEADER', 'Flags'], \
                StartOfObjectHeader)
            OfsName = read_obj_from_buf(buff, self.data_types, \
                ['_OBJECT_HEADER', 'NameInfoOffset'], \
                StartOfObjectHeader)
                
            if OfsName > 0:
                StartOfName = StartOfObjectHeader - OfsName
                Name = read_unicode_string_buf(buff, self.kas, self.data_types, \
                    ['_OBJECT_NAME_INFO', 'Name'], StartOfName)                
            else:
                Name = ''  

            if (Flags & 0x04):
                StartOfObjCreatorInfo = StartOfObjectHeader - \
                    obj_size(self.data_types, '_OBJECT_CREATOR_INFO')
                PID =  read_obj_from_buf(buff, self.data_types, \
                    ['_OBJECT_CREATOR_INFO', 'UniqueProcessId'], \
                    StartOfObjCreatorInfo)
            else:
                PID = None
                
            address = self.as_offset + object_offset
            
            ObjectTypeP = self.as_offset+StartOfObjType            
            if self.reverse_map.has_key(ObjectTypeP & 0xFFFFF000):
                ObjectTypeV = self.reverse_map[ObjectTypeP & 0xFFFFF000]
                ObjectTypeV += ObjectTypeP & 0x00000fff
            else:
                ObjectTypeV = 0
                            
            if (ObjTypeName == Name):
                StrName = Name
            else:
                StrName = "%s (%s)" % (Name, ObjTypeName)
            
            StrObjects = "%d/%d" % (ObjectsCnt, ObjectsHw)
            StrHandles = "%d/%d" % (HandlesCnt, HandlesHw)
            if ((PoolType % 2) == 0):
                StrPoolType = '(npaged)'
            else:
                StrPoolType = '(paged)'
                
            print "0x%08x 0x%08x %4d %4d %9s %9s %4s %-8s 0x%08x %s" % \
                (address, ObjType, Pointers, Handles, \
                StrObjects, StrHandles, \
                PoolTag, StrPoolType, ObjectTypeV, StrName)
                
class objtypescan(forensics.commands.command):

    # Declare meta information associated with this plugin

    meta_info = forensics.commands.command.meta_info
    meta_info['author'] = 'Andreas Schuster'
    meta_info['copyright'] = 'Copyright (c) 2009 Andreas Schuster'
    meta_info['contact'] = 'a.schuster@forensikblog.de'
    meta_info['license'] = 'GNU General Public License 2.0 or later'
    meta_info['url'] = 'http://computer.forensikblog.de/en/'
    meta_info['os'] = 'WIN_32_XP_SP2'
    meta_info['version'] = '0.5'
            
    def help(self):
        return  "Scan for object type objects"
        
    def execute(self):
        op = self.op
        opts = self.opts
           
        (addr_space, symtab, types) = load_and_identify_image(op, opts)
        set_kas(addr_space)
        
        # merge type information and make it globally accessible
        types.update(objtype_types)
        set_datatypes(types)
                     
        try:
            flat_addr_space = FileAddressSpace(opts.filename, fast=True)
        except:
            op.error("Unable to open image file %s" %(opts.filename))
     
        search_addr_space = find_addr_space(flat_addr_space, types)
        scanners = []
        scanners.append((PoolScanObjtype(search_addr_space)))

        print "%-10s %-10s %4s %4s %9s %9s %-13s %-10s %s" % \
            ('Phys.Addr.', 'Obj Type', '#Ptr', '#Hnd', \
            'Objects', 'Handles', 'Pool alloc', 'TypePtr', 'Name')        
        scan_addr_space(search_addr_space, scanners)
